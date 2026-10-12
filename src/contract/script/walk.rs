/// The offset just past the script element at `offset`.
pub fn item_end(script: &[u8], offset: usize) -> Option<usize> {
    crate::primitives::script::read_element(script, offset).map(|(_, next)| next)
}

#[cfg(feature = "std")]
pub fn contains_opcode_pair(script: &[u8], first: u8, second: u8) -> bool {
    let mut offset = 0usize;
    for _ in 0..script.len() {
        let Some(&opcode) = script.get(offset) else {
            return false;
        };
        if opcode == first && script.get(offset.saturating_add(1)) == Some(&second) {
            return true;
        }
        let Some(next) = item_end(script, offset) else {
            return false;
        };
        offset = next;
    }
    false
}
