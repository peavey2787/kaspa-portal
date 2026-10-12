use crate::primitives::opcode::OP_PUSHDATA2;

pub fn scan_raw_for_preimage(raw: &[u8], transaction_id: &[u8]) -> Option<Vec<u8>> {
    for position in 4..raw.len().saturating_sub(50) {
        let Some(script) = candidate_script(raw, transaction_id, position) else {
            continue;
        };
        if let Some(preimage) = first_push(script) {
            return Some(preimage.to_vec());
        }
    }
    None
}

fn candidate_script<'a>(raw: &'a [u8], transaction_id: &[u8], position: usize) -> Option<&'a [u8]> {
    if !candidate_outpoint_matches(raw, transaction_id, position) {
        return None;
    }
    script_after_outpoint(raw, position)
}

fn candidate_outpoint_matches(raw: &[u8], transaction_id: &[u8], position: usize) -> bool {
    raw[position] == 1
        && &raw[position + 1..position + 33] == transaction_id
        && read_u32_length(raw, position - 4) == Some(37)
}

fn script_after_outpoint(raw: &[u8], position: usize) -> Option<&[u8]> {
    let after_outpoint = position.checked_add(37)?;
    let script_length = read_u32_length(raw, after_outpoint)?;
    if !(10..=1000).contains(&script_length) {
        return None;
    }
    let script_start = after_outpoint.checked_add(4)?;
    let script_end = script_start.checked_add(script_length)?;
    raw.get(script_start..script_end)
}

fn read_u32_length(bytes: &[u8], start: usize) -> Option<usize> {
    let end = start.checked_add(4)?;
    let encoded = u32::from_le_bytes(bytes.get(start..end)?.try_into().ok()?);
    usize::try_from(encoded).ok()
}

pub(super) fn first_push(script: &[u8]) -> Option<&[u8]> {
    let (element, _) = crate::primitives::script::read_element(script, 0)?;
    // Direct pushes and OP_PUSHDATA1/2 of 1..=200 bytes carry a preimage.
    (element.opcode <= OP_PUSHDATA2 && valid_push_length(element.data.len()))
        .then_some(element.data)
}

fn valid_push_length(length: usize) -> bool {
    (1..=200).contains(&length)
}
