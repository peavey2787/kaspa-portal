// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

use serde_json::Value;

use super::classification::classify_output_script;
use super::parse_spk_hex;
use crate::transaction::interchange::pskt::exact_json::parse_exact_u64;
use crate::transaction::interchange::pskt::OutputSummary;

pub(crate) fn parse_output_summary(
    out: &Value,
    network_prefix: &str,
) -> Result<OutputSummary, String> {
    let obj = out
        .as_object()
        .ok_or_else(|| "output not object".to_string())?;
    let amount_sompi = parse_exact_u64(
        obj.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let spk_full = obj
        .get("scriptPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (_spk_version, spk_script) = parse_spk_hex(spk_full)?;
    let (kind, address) = classify_output_script(&spk_script, network_prefix);

    Ok(OutputSummary {
        amount_sompi,
        amount_kas: amount_sompi as f64 / 1e8,
        script_kind: kind,
        script_hex: hex::encode(&spk_script),
        address,
    })
}
