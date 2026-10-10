//! Construction of verified witness plans from an authorized compact transaction.

use super::{
    compact, parse_multisig_redeem, VerifiedCovenantRoute, VerifiedInput, VerifiedOutput,
    VerifiedSignature, VerifiedTransaction, VerifiedWitnessItem, VerifiedWitnessPlan,
};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::contract::covenant::execution::WitnessItem;

pub(crate) fn from_compact(
    transaction: compact::Transaction,
) -> Result<VerifiedTransaction, String> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve(transaction.inputs.len())
        .map_err(|_| "verified input allocation failed".to_string())?;
    for (index, input) in transaction.inputs.into_iter().enumerate() {
        let witness = witness_plan(index, &input)?;
        inputs.push(VerifiedInput {
            previous_tx_id: input.tx_id,
            previous_index: input.index,
            amount: input.amount,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.script_version,
            script_public_key: input.script,
            has_covenant_id: input.has_covenant_id,
            witness,
        });
    }

    let outputs = transaction
        .outputs
        .into_iter()
        .map(|output| VerifiedOutput {
            amount: output.amount,
            script_version: output.script_version,
            script_public_key: output.script,
            covenant: output.covenant,
        })
        .collect();

    Ok(VerifiedTransaction {
        version: transaction.version,
        locktime: transaction.locktime,
        subnetwork_id: transaction.subnetwork,
        gas: transaction.gas,
        payload: transaction.payload,
        inputs,
        outputs,
    })
}

pub(crate) fn witness_plan(
    index: usize,
    input: &compact::Input,
) -> Result<VerifiedWitnessPlan, String> {
    if input.redeem.is_empty() {
        return p2pk_witness_plan(index, input);
    }
    require_p2sh_redeem_binding(index, &input.script, &input.redeem)?;
    if let Some(specialized) = &input.specialized_witness {
        return specialized_witness_plan(specialized);
    }
    if let Some((threshold, _)) = parse_multisig_redeem(&input.redeem) {
        return multisig_witness_plan(index, input, threshold);
    }
    covenant_witness_plan(index, input)
}

pub(crate) fn p2pk_witness_plan(
    index: usize,
    input: &compact::Input,
) -> Result<VerifiedWitnessPlan, String> {
    require_p2pk_script(index, &input.script)?;
    let signature = exactly_one_signature(index, &input.signatures)?;
    if signature.position != 0 {
        return Err(format!(
            "input[{index}] P2PK signature position must be zero"
        ));
    }
    Ok(VerifiedWitnessPlan::P2pk {
        signature: copy_signature(signature),
    })
}

pub(crate) fn specialized_witness_plan(
    specialized: &compact::SpecializedWitness,
) -> Result<VerifiedWitnessPlan, String> {
    let route = match specialized.route {
        compact::SpecializedRoute::PrivateSwapClaim => VerifiedCovenantRoute::PrivateSwapClaim,
        compact::SpecializedRoute::OracleV1Claim => VerifiedCovenantRoute::OracleV1Claim,
        compact::SpecializedRoute::CommitRevealClaim => VerifiedCovenantRoute::CommitRevealClaim,
        compact::SpecializedRoute::MerkleClaim => VerifiedCovenantRoute::MerkleClaim,
    };
    Ok(VerifiedWitnessPlan::SpecializedCovenant {
        route,
        signature_script: specialized.signature_script.clone(),
        supplied_mask: specialized.supplied_mask,
        supplied_true_mask: specialized.supplied_true_mask,
    })
}

pub(crate) fn multisig_witness_plan(
    index: usize,
    input: &compact::Input,
    threshold: u8,
) -> Result<VerifiedWitnessPlan, String> {
    if input.signatures.len() != usize::from(threshold) {
        return Err(format!(
            "input[{index}] verified multisig witness has {} signatures, expected {threshold}",
            input.signatures.len()
        ));
    }
    let mut signatures = input
        .signatures
        .iter()
        .map(copy_signature)
        .collect::<Vec<_>>();
    signatures.sort_by_key(|signature| signature.position);
    Ok(VerifiedWitnessPlan::Multisig {
        threshold,
        signatures,
        redeem_script: input.redeem.clone(),
    })
}

pub(crate) fn covenant_witness_plan(
    index: usize,
    input: &compact::Input,
) -> Result<VerifiedWitnessPlan, String> {
    // Completion verification already required exactly the path's signatures.
    let (supplied_mask, supplied_true_mask, path) = compact::covenant_path(index, input)?;
    let witness = path
        .iter()
        .map(|item| match item {
            WitnessItem::Selector(value) => Ok(VerifiedWitnessItem::Selector(*value)),
            WitnessItem::Signature { position } => input
                .signatures
                .iter()
                .find(|signature| signature.position == *position)
                .map(|signature| VerifiedWitnessItem::Signature(copy_signature(signature)))
                .ok_or_else(|| format!("input[{index}] covenant path signature is missing")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedWitnessPlan::Covenant {
        witness,
        redeem_script: input.redeem.clone(),
        supplied_mask,
        supplied_true_mask,
    })
}

pub(crate) fn exactly_one_signature(
    index: usize,
    signatures: &[compact::Signature],
) -> Result<&compact::Signature, String> {
    if signatures.len() != 1 {
        return Err(format!(
            "input[{index}] witness plan requires exactly one verified signature, got {}",
            signatures.len()
        ));
    }
    signatures
        .first()
        .ok_or_else(|| format!("input[{index}] verified signature is missing"))
}

pub(crate) fn copy_signature(signature: &compact::Signature) -> VerifiedSignature {
    VerifiedSignature {
        position: signature.position,
        sighash: signature.sighash,
        bytes: signature.bytes,
    }
}

pub(crate) fn require_p2pk_script(index: usize, script: &[u8]) -> Result<(), String> {
    if script.len() == 34 && script.first() == Some(&0x20) && script.get(33) == Some(&0xac) {
        Ok(())
    } else {
        Err(format!(
            "input[{index}] signature without redeemScript is not canonical P2PK"
        ))
    }
}

pub(crate) fn require_p2sh_redeem_binding(
    index: usize,
    script: &[u8],
    redeem: &[u8],
) -> Result<(), String> {
    if script.len() != 35
        || script.first() != Some(&0xaa)
        || script.get(1) != Some(&0x20)
        || script.get(34) != Some(&0x87)
    {
        return Err(format!(
            "input[{index}] redeemScript is present but scriptPublicKey is not canonical P2SH"
        ));
    }
    let hash = blake2b_simd::Params::new().hash_length(32).hash(redeem);
    if script.get(2..34) != Some(hash.as_bytes()) {
        return Err(format!(
            "input[{index}] redeemScript hash does not match scriptPublicKey"
        ));
    }
    Ok(())
}
