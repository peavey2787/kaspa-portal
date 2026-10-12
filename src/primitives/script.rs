//! The one reader for Kaspa script elements: an opcode and the bytes it
//! pushes. Every script walker in Portal decodes pushes through here.

use super::opcode::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};

/// One script element. Non-push opcodes, `OP_0` and small integers carry no data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    pub opcode: u8,
    pub data: &'a [u8],
}

impl Element<'_> {
    /// Whether this element pushes bytes (`OP_0` and `0x01..=OP_PUSHDATA4`).
    #[must_use]
    pub const fn is_push(&self) -> bool {
        self.opcode <= OP_PUSHDATA4
    }
}

/// Read the element at `at`, returning it and the offset just past it (always
/// greater than `at`). `None` when `at` is past the end or a push is truncated.
#[must_use]
pub fn read_element(script: &[u8], at: usize) -> Option<(Element<'_>, usize)> {
    let opcode = *script.get(at)?;
    let (header, length) = match opcode {
        0x01..=0x4b => (1, usize::from(opcode)),
        OP_PUSHDATA1 => (2, usize::from(*script.get(at + 1)?)),
        OP_PUSHDATA2 => (3, usize::from(u16::from_le_bytes(little(script, at + 1)?))),
        OP_PUSHDATA4 => (
            5,
            usize::try_from(u32::from_le_bytes(little(script, at + 1)?)).ok()?,
        ),
        // OP_0 and every non-push opcode are a single byte.
        _ => (1, 0),
    };
    let start = at.checked_add(header)?;
    let end = start.checked_add(length)?;
    Some((
        Element {
            opcode,
            data: script.get(start..end)?,
        },
        end,
    ))
}

fn little<const N: usize>(script: &[u8], at: usize) -> Option<[u8; N]> {
    script.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Every element of `script` in order; stops at the first malformed one,
/// which [`Elements::is_complete`] then reports.
#[must_use]
pub const fn elements(script: &[u8]) -> Elements<'_> {
    Elements {
        script,
        at: 0,
        malformed: false,
    }
}

/// Iterator over the elements of a script.
#[derive(Clone, Debug)]
pub struct Elements<'a> {
    script: &'a [u8],
    at: usize,
    malformed: bool,
}

impl Elements<'_> {
    /// True once every byte was consumed as well-formed elements.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        !self.malformed && self.at == self.script.len()
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        if self.malformed || self.at == self.script.len() {
            return None;
        }
        let Some((element, next)) = read_element(self.script, self.at) else {
            self.malformed = true;
            return None;
        };
        self.at = next;
        Some(element)
    }
}

#[cfg(test)]
#[path = "unit-tests/script.rs"]
mod unit_tests;
