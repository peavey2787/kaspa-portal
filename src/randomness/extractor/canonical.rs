use crate::{
    primitives::NetworkId,
    randomness::source::{curby::CurbyEvidence, kaspa::KaspaEntropyEvidence},
};

pub struct CanonicalEvidence {
    pub bytes: Vec<u8>,
    pub bit_len: usize,
}

pub fn canonical_evidence(
    network: NetworkId,
    kaspa: &[KaspaEntropyEvidence],
    curby: Option<&CurbyEvidence>,
) -> Result<CanonicalEvidence, String> {
    validate_kaspa_count(kaspa)?;

    let extra = curby.map(|evidence| evidence.value.len()).unwrap_or(0);
    let mut output = Vec::with_capacity(64 + kaspa.len() * 48 + extra);
    output.extend_from_slice(b"kaspa-portal/beacon/evidence/v1\0");
    output.push(network_code(network));
    output.extend_from_slice(&(kaspa.len() as u16).to_be_bytes());
    append_kaspa_evidence(&mut output, kaspa)?;
    append_curby_evidence(&mut output, curby)?;

    let bit_len = output
        .len()
        .checked_mul(8)
        .ok_or("evidence length overflow")?;
    Ok(CanonicalEvidence {
        bytes: output,
        bit_len,
    })
}

fn validate_kaspa_count(kaspa: &[KaspaEntropyEvidence]) -> Result<(), String> {
    if kaspa.is_empty() {
        return Err("at least one Kaspa block hash is required".into());
    }
    if kaspa.len() > 256 {
        return Err("Kaspa evidence exceeds 256 blocks".into());
    }
    Ok(())
}

fn append_kaspa_evidence(
    output: &mut Vec<u8>,
    kaspa: &[KaspaEntropyEvidence],
) -> Result<(), String> {
    let mut previous_daa_score = None;
    for evidence in kaspa {
        evidence.validate()?;
        ensure_monotonic(previous_daa_score, evidence.daa_score)?;
        previous_daa_score = evidence.daa_score.or(previous_daa_score);
        output.extend_from_slice(&evidence.block_hash);
        append_optional_u64(output, evidence.daa_score);
    }
    Ok(())
}

fn ensure_monotonic(previous: Option<u64>, current: Option<u64>) -> Result<(), String> {
    if let (Some(previous), Some(current)) = (previous, current) {
        if current < previous {
            return Err("Kaspa evidence DAA scores must be nondecreasing".into());
        }
    }
    Ok(())
}

fn append_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn append_curby_evidence(
    output: &mut Vec<u8>,
    curby: Option<&CurbyEvidence>,
) -> Result<(), String> {
    let Some(curby) = curby else {
        output.push(0);
        return Ok(());
    };

    curby.validate()?;
    output.push(1);
    output.extend_from_slice(&(curby.round.len() as u16).to_be_bytes());
    output.extend_from_slice(curby.round.as_bytes());
    output.extend_from_slice(&(curby.value.len() as u16).to_be_bytes());
    output.extend_from_slice(&curby.value);
    output.extend_from_slice(&curby.raw_response_hash);
    Ok(())
}

fn network_code(network: NetworkId) -> u8 {
    match network {
        NetworkId::Mainnet => 0,
        NetworkId::Testnet(10) => 10,
        NetworkId::Testnet(11) => 11,
        NetworkId::Testnet(12) => 12,
        // Preserve the historical codes for TN10/TN11/TN12. Future
        // user-configurable testnets get a distinct domain-separation byte.
        NetworkId::Testnet(suffix) => 0x80 | suffix,
        NetworkId::Simnet => 20,
        NetworkId::Devnet => 21,
    }
}
