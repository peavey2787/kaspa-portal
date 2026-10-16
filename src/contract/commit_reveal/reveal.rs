//! A commit-reveal reveal spend, read back from its signature script.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::primitives::{hash::blake2b_256, opcode::OP_0};

use super::script::{commit_reveal_script_fields, CommitRevealFields};

/// The preimage a reveal spend disclosed and the commit-reveal script it opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRevealReveal {
    /// Both revealed parts, concatenated in order.
    pub preimage: Vec<u8>,
    pub fields: CommitRevealFields,
}

impl CommitRevealReveal {
    /// Whether the preimage hashes to the committed BLAKE2b hash.
    #[must_use]
    pub fn matches(&self) -> bool {
        blake2b_256(&self.preimage) == self.fields.committed_hash
    }
}

/// Read `<part A> <part B> <signature> OP_0 <redeem script>`, the signature
/// script of a reveal spend; `None` for anything else.
#[must_use]
pub fn read_commit_reveal_reveal(signature_script: &[u8]) -> Option<CommitRevealReveal> {
    let elements = crate::contract::script::complete_elements(signature_script)?;
    let [part_a, part_b, signature, selector, redeem] = elements.as_slice() else {
        return None;
    };
    let pushes = [part_a, part_b, signature, redeem];
    if selector.opcode != OP_0 || !pushes.iter().all(|element| element.is_push()) {
        return None;
    }
    Some(CommitRevealReveal {
        preimage: [part_a.data, part_b.data].concat(),
        fields: commit_reveal_script_fields(redeem.data)?,
    })
}
