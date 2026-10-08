//! Witness consumption order along one fully selected covenant path.
//!
//! Given a complete selector assignment, walk the script's control flow and
//! record, in execution order, every witness item the taken path consumes:
//! an IF/NOTIF selector or the signature for a canonically pushed key. Keys
//! are numbered exactly as [`super::branch::resolve_covenant_branches`]
//! numbers them, so a position here names the same key occurrence there.
//!
//! The taken path is refused if it reaches any other signature check
//! (multisig, data signatures, or a key that was not pushed immediately
//! before CHECKSIG/CHECKSIGVERIFY): such spends need a typed plan of their own.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use super::branch::{
    advance_push, pushdata_lengths, MAX_COVENANT_BRANCH_DEPTH, MAX_COVENANT_BRANCH_KEYS,
};

const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DATA_32: u8 = 0x20;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
/// Signature checks a selector/signature witness cannot satisfy.
const UNSUPPORTED_CHECKS: [u8; 4] = [0xab, 0xae, 0xaf, 0xd7];

/// One witness stack item consumed by the taken path, in consumption order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessItem {
    /// An IF/NOTIF selector and the value the spender supplies.
    Selector(bool),
    /// The signature for the key occurrence at this resolver position.
    Signature { position: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Control flow or a push is malformed.
    MalformedScript,
    /// More nested branches or selectors than a covenant may use.
    BranchDepthExceeded,
    /// More canonical signature keys than a covenant may use.
    TooManyKeys,
    /// The assignment does not set exactly the script's selector bits.
    IncompleteSelectors,
    /// The taken path reaches a signature check this plan cannot satisfy.
    UnsupportedSignatureCheck,
}

#[derive(Clone, Copy)]
struct Frame {
    parent_executing: bool,
    taken: bool,
    in_else: bool,
}

struct Trace<'a> {
    script: &'a [u8],
    supplied_mask: u16,
    supplied_true_mask: u16,
    frames: [Frame; MAX_COVENANT_BRANCH_DEPTH],
    depth: usize,
    next_branch: u32,
    next_key: usize,
    selector_mask: u16,
    after_key_push: bool,
    items: Vec<WitnessItem>,
}

impl<'a> Trace<'a> {
    fn executing(&self) -> bool {
        self.frames[..self.depth]
            .iter()
            .all(|frame| frame.parent_executing && (frame.taken != frame.in_else))
    }

    fn enter_branch(&mut self, opcode: u8) -> Result<(), ExecutionError> {
        if self.depth >= MAX_COVENANT_BRANCH_DEPTH || self.next_branch >= 16 {
            return Err(ExecutionError::BranchDepthExceeded);
        }
        let bit = 1u16 << self.next_branch;
        self.next_branch += 1;
        self.selector_mask |= bit;
        let executing = self.executing();
        let mut taken = false;
        if executing {
            let value = self.supplied_true_mask & bit != 0;
            self.items.push(WitnessItem::Selector(value));
            taken = value == (opcode == OP_IF);
        }
        self.frames[self.depth] = Frame {
            parent_executing: executing,
            taken,
            in_else: false,
        };
        self.depth += 1;
        Ok(())
    }

    fn enter_else(&mut self) -> Result<(), ExecutionError> {
        let frame = self
            .depth
            .checked_sub(1)
            .map(|top| &mut self.frames[top])
            .ok_or(ExecutionError::MalformedScript)?;
        if frame.in_else {
            return Err(ExecutionError::MalformedScript);
        }
        frame.in_else = true;
        Ok(())
    }

    fn leave_branch(&mut self) -> Result<(), ExecutionError> {
        self.depth = self
            .depth
            .checked_sub(1)
            .ok_or(ExecutionError::MalformedScript)?;
        Ok(())
    }

    fn key_push(&mut self, position: usize) -> Result<usize, ExecutionError> {
        let end = position
            .checked_add(33)
            .filter(|end| *end <= self.script.len())
            .ok_or(ExecutionError::MalformedScript)?;
        if matches!(
            self.script.get(end),
            Some(&OP_CHECKSIG | &OP_CHECKSIGVERIFY)
        ) {
            if self.next_key >= MAX_COVENANT_BRANCH_KEYS {
                return Err(ExecutionError::TooManyKeys);
            }
            let position = u8::try_from(self.next_key).map_err(|_| ExecutionError::TooManyKeys)?;
            self.next_key += 1;
            if self.executing() {
                self.items.push(WitnessItem::Signature { position });
            }
            self.after_key_push = true;
        }
        Ok(end)
    }

    fn signature_check(&mut self, opcode: u8, after_key_push: bool) -> Result<(), ExecutionError> {
        let canonical = matches!(opcode, OP_CHECKSIG | OP_CHECKSIGVERIFY) && after_key_push;
        let unsupported = UNSUPPORTED_CHECKS.contains(&opcode)
            || matches!(opcode, OP_CHECKSIG | OP_CHECKSIGVERIFY);
        if unsupported && !canonical && self.executing() {
            return Err(ExecutionError::UnsupportedSignatureCheck);
        }
        Ok(())
    }

    /// Execute the opcode at `position`; returns the offset its operands end
    /// at, or 0 when it has none to skip.
    fn step(&mut self, position: usize, opcode: u8) -> Result<usize, ExecutionError> {
        let after_key_push = core::mem::take(&mut self.after_key_push);
        match opcode {
            OP_IF | OP_NOTIF => self.enter_branch(opcode),
            OP_ELSE => self.enter_else(),
            OP_ENDIF => self.leave_branch(),
            OP_DATA_32 => return self.key_push(position),
            0x01..=0x4e => return self.skip_push(position, opcode),
            _ => self.signature_check(opcode, after_key_push),
        }?;
        Ok(0)
    }

    fn skip_push(&self, position: usize, opcode: u8) -> Result<usize, ExecutionError> {
        let malformed = |_| ExecutionError::MalformedScript;
        let (header, payload) =
            pushdata_lengths(self.script, position, opcode).map_err(malformed)?;
        advance_push(self.script, position, header, payload).map_err(malformed)
    }

    fn finish(self) -> Result<Vec<WitnessItem>, ExecutionError> {
        if self.depth != 0 {
            return Err(ExecutionError::MalformedScript);
        }
        if self.supplied_mask != self.selector_mask
            || self.supplied_true_mask & !self.supplied_mask != 0
        {
            return Err(ExecutionError::IncompleteSelectors);
        }
        Ok(self.items)
    }
}

/// Witness items the path chosen by a complete selector assignment consumes,
/// in the order the script consumes them.
pub fn trace_witness(
    script: &[u8],
    supplied_mask: u16,
    supplied_true_mask: u16,
) -> Result<Vec<WitnessItem>, ExecutionError> {
    let mut trace = Trace {
        script,
        supplied_mask,
        supplied_true_mask,
        frames: [Frame {
            parent_executing: true,
            taken: true,
            in_else: false,
        }; MAX_COVENANT_BRANCH_DEPTH],
        depth: 0,
        next_branch: 0,
        next_key: 0,
        selector_mask: 0,
        after_key_push: false,
        items: Vec::new(),
    };
    // Iterating positions bounds the walk; pushes only skip ahead.
    let mut operands_end = 0;
    for (position, &opcode) in script.iter().enumerate() {
        if position >= operands_end {
            operands_end = trace.step(position, opcode)?;
        }
    }
    trace.finish()
}

#[cfg(test)]
#[path = "unit-tests/execution.rs"]
mod unit_tests;
