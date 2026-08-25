// Kaspa Portal — consensus transaction finalization
// License: GPL-3.0

use serde_json::{Map, Value};

use crate::transaction::interchange::pskt::exact_json::parse_exact_u64;

use super::{build_consensus_input, build_consensus_output};
use crate::transaction::interchange::pskt::scripts::compute_genesis_covenant_id;
use crate::transaction::interchange::pskt::wire::{decode_root, pskt_from_root};

pub(crate) struct FinalizedConsensusTransaction {
    pub(crate) tx_version: u16,
    pub(crate) inputs: Vec<crate::transaction::consensus::ConsensusInput>,
    pub(crate) outputs: Vec<crate::transaction::consensus::ConsensusOutput>,
    pub(crate) locktime: u64,
    pub(crate) subnetwork_id: [u8; 20],
    pub(crate) gas: u64,
    pub(crate) payload: Vec<u8>,
}

impl FinalizedConsensusTransaction {
    pub(crate) fn into_consensus_transaction(
        self,
    ) -> crate::transaction::consensus::ConsensusTransaction {
        crate::transaction::consensus::ConsensusTransaction {
            tx_version: self.tx_version,
            input_encoding: crate::transaction::consensus::InputEncoding::Budgeted,
            inputs: self.inputs,
            outputs: self.outputs,
            locktime: self.locktime,
            subnetwork_id: self.subnetwork_id,
            gas: self.gas,
            payload: self.payload,
        }
    }
}

pub(crate) fn finalize_to_consensus(
    wire_hex: &str,
) -> Result<FinalizedConsensusTransaction, String> {
    let (format, root) = decode_root(wire_hex)?;
    let pskt = pskt_from_root(&root, format)?;
    let document = pskt
        .as_object()
        .ok_or_else(|| "PSKT not object".to_string())?;
    let global = document
        .get("global")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing global".to_string())?;
    let settings = ConsensusSettings::parse(global)?;
    let input_values = document
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing inputs".to_string())?;
    let output_values = document
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing outputs".to_string())?;

    let inputs = build_inputs(input_values, &settings)?;
    let mut outputs = build_outputs(output_values)?;
    apply_persistent_vault_binding(input_values, &inputs, &mut outputs);

    Ok(FinalizedConsensusTransaction {
        tx_version: settings.tx_version,
        inputs,
        outputs,
        locktime: settings.locktime,
        subnetwork_id: settings.subnetwork_id,
        gas: settings.gas,
        payload: settings.payload,
    })
}

struct ConsensusSettings {
    tx_version: u16,
    locktime: u64,
    force_beneficiary: bool,
    force_time_path: bool,
    escrow_branch: Option<String>,
    ship_branch: Option<String>,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

impl ConsensusSettings {
    fn parse(global: &Map<String, Value>) -> Result<Self, String> {
        let header = parse_transaction_header(global)?;
        let branches = parse_branch_settings(global, header.locktime)?;
        let network = parse_network_settings(global)?;

        Ok(Self {
            tx_version: header.tx_version,
            locktime: header.locktime,
            force_beneficiary: branches.force_beneficiary,
            force_time_path: branches.force_time_path,
            escrow_branch: branches.escrow_branch,
            ship_branch: branches.ship_branch,
            subnetwork_id: network.subnetwork_id,
            gas: network.gas,
            payload: network.payload,
        })
    }
}

struct TransactionHeader {
    tx_version: u16,
    locktime: u64,
}

fn parse_transaction_header(global: &Map<String, Value>) -> Result<TransactionHeader, String> {
    let tx_version_value = global
        .get("txVersion")
        .ok_or_else(|| "missing txVersion".to_string())?;
    let tx_version_value = tx_version_value
        .as_u64()
        .ok_or_else(|| "txVersion must be an unsigned integer".to_string())?;
    let tx_version =
        u16::try_from(tx_version_value).map_err(|_| "txVersion exceeds u16 range".to_string())?;

    Ok(TransactionHeader {
        tx_version,
        locktime: optional_exact_u64(global, "fallbackLockTime")?,
    })
}

struct BranchSettings {
    force_beneficiary: bool,
    force_time_path: bool,
    escrow_branch: Option<String>,
    ship_branch: Option<String>,
}

fn parse_branch_settings(
    global: &Map<String, Value>,
    locktime: u64,
) -> Result<BranchSettings, String> {
    let covenant_branch = optional_string(global, "covenantBranch")?;
    let proprietary = optional_object(global, "proprietaries")?;

    Ok(BranchSettings {
        force_beneficiary: covenant_branch == Some("beneficiary"),
        force_time_path: covenant_branch == Some("owner-time") || locktime > 0,
        escrow_branch: string_field(proprietary, "escrowBranch")?,
        ship_branch: string_field(proprietary, "shipBranch")?,
    })
}

struct NetworkSettings {
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

fn parse_network_settings(global: &Map<String, Value>) -> Result<NetworkSettings, String> {
    Ok(NetworkSettings {
        subnetwork_id: crate::transaction::interchange::pskt::wire::decode_subnetwork_id(global)?,
        gas: optional_exact_u64(global, "gas")?,
        payload: optional_hex(global, "txPayload")?,
    })
}

fn optional_exact_u64(values: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match values.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => parse_exact_u64(value, key),
    }
}

fn build_inputs(
    values: &[Value],
    settings: &ConsensusSettings,
) -> Result<Vec<crate::transaction::consensus::ConsensusInput>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, input)| {
            build_consensus_input(
                input,
                settings.force_beneficiary,
                settings.force_time_path,
                &settings.escrow_branch,
                &settings.ship_branch,
            )
            .map_err(|error| format!("input[{}]: {}", index, error))
        })
        .collect()
}

fn build_outputs(
    values: &[Value],
) -> Result<Vec<crate::transaction::consensus::ConsensusOutput>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, output)| {
            build_consensus_output(output).map_err(|error| format!("output[{}]: {}", index, error))
        })
        .collect()
}

fn apply_persistent_vault_binding(
    input_values: &[Value],
    inputs: &[crate::transaction::consensus::ConsensusInput],
    outputs: &mut [crate::transaction::consensus::ConsensusOutput],
) {
    let is_persistent_vault = input_values.iter().any(|input| {
        input
            .get("proprietaries")
            .and_then(|value| value.get("persistentVault"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    let (Some(input), Some(output)) = (inputs.first(), outputs.first_mut()) else {
        return;
    };
    if !is_persistent_vault || output.covenant.is_some() {
        return;
    }

    let covenant_id = compute_genesis_covenant_id(
        &input.prev_tx_id,
        input.prev_index,
        0,
        output.value,
        output.spk_version,
        &output.spk_script,
    );
    output.covenant = Some((0, covenant_id));
}

fn optional_string<'a>(
    values: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match values.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn optional_object<'a>(
    values: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match values.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(format!("{key} must be an object")),
    }
}

fn optional_hex(values: &Map<String, Value>, key: &str) -> Result<Vec<u8>, String> {
    let Some(value) = optional_string(values, key)? else {
        return Ok(Vec::new());
    };
    hex::decode(value).map_err(|_| format!("invalid {key} hex"))
}

fn string_field(
    proprietary: Option<&Map<String, Value>>,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(proprietary) = proprietary else {
        return Ok(None);
    };
    Ok(optional_string(proprietary, key)?.map(str::to_owned))
}
