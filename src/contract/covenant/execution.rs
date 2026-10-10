//! Witness consumption order along one fully selected covenant path.
//!
//! Given a complete selector assignment, walk the script's control flow while
//! tracking which stack items the script itself produced, and record in
//! execution order every witness item the taken path consumes: an IF/NOTIF
//! selector or the signature for a canonically pushed key. Keys are numbered
//! exactly as [`super::branch::resolve_covenant_branches`] numbers them, so a
//! position here names the same key occurrence there.
//!
//! An IF/NOTIF whose condition the script computed is not a witness selector:
//! both of its arms must then be pure script logic with the same stack effect.
//! The taken path is refused whenever it would need any other witness data,
//! reaches a signature check other than CHECKSIG/CHECKSIGVERIFY on a key pushed
//! immediately before it, or uses an opcode whose stack effect is not modelled
//! here: such spends need a typed plan of their own.

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
/// Signature checks a selector/signature witness cannot satisfy on their own.
const SIGNATURE_CHECKS: [u8; 6] = [0xab, OP_CHECKSIG, OP_CHECKSIGVERIFY, 0xae, 0xaf, 0xd7];

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
    /// The taken path uses an opcode whose stack effect is not modelled.
    UnsupportedOpcode,
    /// The taken path consumes witness data other than selectors and signatures.
    WitnessDataRequired,
    /// A computed branch's arms differ in stack effect or need witness items.
    DataDependentBranch,
}

/// One parsed script element.
enum Node {
    /// Any data push, including small integers.
    Push,
    /// `<32-byte key> CHECKSIG|CHECKSIGVERIFY` at a resolver key position.
    KeyCheck { position: u8, verify: bool },
    /// Any other opcode.
    Op(u8),
    /// IF/NOTIF at a resolver selector bit, with both arms.
    Branch {
        bit: u16,
        notif: bool,
        then: Vec<Node>,
        otherwise: Vec<Node>,
    },
}

struct OpenBranch {
    bit: u16,
    notif: bool,
    then: Vec<Node>,
    otherwise: Option<Vec<Node>>,
}

struct Parser<'a> {
    script: &'a [u8],
    open: Vec<OpenBranch>,
    root: Vec<Node>,
    next_branch: u32,
    next_key: usize,
}

impl Parser<'_> {
    fn current(&mut self) -> &mut Vec<Node> {
        match self.open.last_mut() {
            Some(OpenBranch {
                otherwise: Some(otherwise),
                ..
            }) => otherwise,
            Some(branch) => &mut branch.then,
            None => &mut self.root,
        }
    }

    fn enter_branch(&mut self, opcode: u8) -> Result<(), ExecutionError> {
        if self.open.len() >= MAX_COVENANT_BRANCH_DEPTH || self.next_branch >= 16 {
            return Err(ExecutionError::BranchDepthExceeded);
        }
        let bit = 1u16 << self.next_branch;
        self.next_branch += 1;
        self.open.push(OpenBranch {
            bit,
            notif: opcode == OP_NOTIF,
            then: Vec::new(),
            otherwise: None,
        });
        Ok(())
    }

    fn enter_else(&mut self) -> Result<(), ExecutionError> {
        match self.open.last_mut() {
            Some(branch) if branch.otherwise.is_none() => {
                branch.otherwise = Some(Vec::new());
                Ok(())
            }
            _ => Err(ExecutionError::MalformedScript),
        }
    }

    fn leave_branch(&mut self) -> Result<(), ExecutionError> {
        let branch = self.open.pop().ok_or(ExecutionError::MalformedScript)?;
        let node = Node::Branch {
            bit: branch.bit,
            notif: branch.notif,
            then: branch.then,
            otherwise: branch.otherwise.unwrap_or_default(),
        };
        self.current().push(node);
        Ok(())
    }

    /// A 32-byte push directly followed by CHECKSIG/CHECKSIGVERIFY is a key;
    /// returns the offset the element ends at.
    fn key_push(&mut self, position: usize) -> Result<usize, ExecutionError> {
        let end = position
            .checked_add(33)
            .filter(|end| *end <= self.script.len())
            .ok_or(ExecutionError::MalformedScript)?;
        let check = self.script.get(end).copied();
        if !matches!(check, Some(OP_CHECKSIG | OP_CHECKSIGVERIFY)) {
            self.current().push(Node::Push);
            return Ok(end);
        }
        if self.next_key >= MAX_COVENANT_BRANCH_KEYS {
            return Err(ExecutionError::TooManyKeys);
        }
        let position = u8::try_from(self.next_key).map_err(|_| ExecutionError::TooManyKeys)?;
        self.next_key += 1;
        let verify = check == Some(OP_CHECKSIGVERIFY);
        self.current().push(Node::KeyCheck { position, verify });
        Ok(end + 1)
    }

    fn data_push(&mut self, position: usize, opcode: u8) -> Result<usize, ExecutionError> {
        let malformed = |_| ExecutionError::MalformedScript;
        let (header, payload) =
            pushdata_lengths(self.script, position, opcode).map_err(malformed)?;
        let end = advance_push(self.script, position, header, payload).map_err(malformed)?;
        self.current().push(Node::Push);
        Ok(end)
    }

    /// Parse the element at `position`; returns the offset its operands end
    /// at, or 0 when it has none to skip.
    fn element(&mut self, position: usize, opcode: u8) -> Result<usize, ExecutionError> {
        match opcode {
            OP_IF | OP_NOTIF => self.enter_branch(opcode),
            OP_ELSE => self.enter_else(),
            OP_ENDIF => self.leave_branch(),
            OP_DATA_32 => return self.key_push(position),
            0x01..=0x4e => return self.data_push(position, opcode),
            0x00 | 0x4f | 0x51..=0x60 => {
                self.current().push(Node::Push);
                Ok(())
            }
            _ => {
                self.current().push(Node::Op(opcode));
                Ok(())
            }
        }?;
        Ok(0)
    }

    fn parse(mut self) -> Result<(Vec<Node>, u16), ExecutionError> {
        // Iterating positions bounds the walk; elements only skip ahead.
        let mut operands_end = 0;
        for (position, &opcode) in self.script.iter().enumerate() {
            if position >= operands_end {
                operands_end = self.element(position, opcode)?;
            }
        }
        if !self.open.is_empty() {
            return Err(ExecutionError::MalformedScript);
        }
        let selector_mask = ((1u32 << self.next_branch) - 1) as u16;
        Ok((self.root, selector_mask))
    }
}

/// Stack items an opcode pops and pushes, for opcodes whose effect is fixed.
const fn stack_effect(opcode: u8) -> Option<(usize, usize)> {
    Some(match opcode {
        0x61 => (0, 0),                                                  // NOP
        0x69 | 0x75 | 0xb0 | 0xb1 => (1, 0),                             // VERIFY DROP CLTV CSV
        0x6d => (2, 0),                                                  // 2DROP
        0x6e => (2, 4),                                                  // 2DUP
        0x76 | 0x82 => (1, 2),                                           // DUP SIZE
        0x77 => (2, 1),                                                  // NIP
        0x78 | 0x7d => (2, 3),                                           // OVER TUCK
        0x7b => (3, 3),                                                  // ROT
        0x7c => (2, 2),                                                  // SWAP
        0x7f | 0xa5 => (3, 1),                                           // SUBSTR WITHIN
        0x88 | 0x9d => (2, 0), // EQUALVERIFY NUMEQUALVERIFY
        0x8b | 0x8c | 0x8f..=0x92 | 0xa8 | 0xaa => (1, 1), // unary math, SHA256, BLAKE2B
        0x7e | 0x87 | 0x93 | 0x94 | 0x9a..=0x9c | 0x9e..=0xa4 => (2, 1), // binary ops
        0xb3 | 0xb4 | 0xb9 => (0, 1), // input/output count, input index
        0xbe | 0xbf | 0xc2 | 0xc3 | 0xcf | 0xd2 => (1, 1), // per-index introspection
        0xd3 => (2, 1),        // covenant output index
        _ => return None,
    })
}

fn opcode_error(opcode: u8) -> ExecutionError {
    if SIGNATURE_CHECKS.contains(&opcode) {
        ExecutionError::UnsupportedSignatureCheck
    } else {
        ExecutionError::UnsupportedOpcode
    }
}

/// Items a pure block needs below it, and its net stack effect.
fn pure_effect(nodes: &[Node]) -> Result<(usize, isize), ExecutionError> {
    let mut depth = 0isize;
    let mut need = 0isize;
    for node in nodes {
        let (pops, pushes) = match node {
            Node::Push => (0, 1),
            Node::KeyCheck { .. } => return Err(ExecutionError::DataDependentBranch),
            Node::Op(opcode) => stack_effect(*opcode).ok_or_else(|| opcode_error(*opcode))?,
            Node::Branch {
                then, otherwise, ..
            } => {
                // The condition pops one item; the arms' need already counts
                // from below it, so it subsumes that pop's own need.
                depth -= 1;
                let (then_need, delta) = arms_effect(then, otherwise)?;
                need = need.max(then_need - depth);
                depth += delta;
                continue;
            }
        };
        depth -= pops as isize;
        need = need.max(-depth);
        depth += pushes as isize;
    }
    Ok((need as usize, depth))
}

/// Both arms of a computed branch must agree on their stack effect.
fn arms_effect(then: &[Node], otherwise: &[Node]) -> Result<(isize, isize), ExecutionError> {
    let (then_need, then_delta) = pure_effect(then)?;
    let (else_need, else_delta) = pure_effect(otherwise)?;
    if then_delta != else_delta {
        return Err(ExecutionError::DataDependentBranch);
    }
    Ok((then_need.max(else_need) as isize, then_delta))
}

struct Walk {
    supplied_true_mask: u16,
    produced: usize,
    items: Vec<WitnessItem>,
}

impl Walk {
    fn pop(&mut self, count: usize) -> Result<(), ExecutionError> {
        self.produced = self
            .produced
            .checked_sub(count)
            .ok_or(ExecutionError::WitnessDataRequired)?;
        Ok(())
    }

    fn run(&mut self, nodes: &[Node]) -> Result<(), ExecutionError> {
        nodes.iter().try_for_each(|node| self.step(node))
    }

    fn step(&mut self, node: &Node) -> Result<(), ExecutionError> {
        match node {
            Node::Push => self.produced += 1,
            Node::KeyCheck { position, verify } => {
                // The signature sits directly beneath the key: it must come
                // from the witness, not from data the script pushed.
                if self.produced != 0 {
                    return Err(ExecutionError::UnsupportedSignatureCheck);
                }
                self.items.push(WitnessItem::Signature {
                    position: *position,
                });
                self.produced = usize::from(!*verify);
            }
            Node::Op(opcode) => {
                let (pops, pushes) = stack_effect(*opcode).ok_or_else(|| opcode_error(*opcode))?;
                self.pop(pops)?;
                self.produced += pushes;
            }
            Node::Branch {
                bit,
                notif,
                then,
                otherwise,
            } => return self.branch(*bit, *notif, then, otherwise),
        }
        Ok(())
    }

    fn branch(
        &mut self,
        bit: u16,
        notif: bool,
        then: &[Node],
        otherwise: &[Node],
    ) -> Result<(), ExecutionError> {
        if self.produced == 0 {
            let value = self.supplied_true_mask & bit != 0;
            self.items.push(WitnessItem::Selector(value));
            return self.run(if value != notif { then } else { otherwise });
        }
        self.pop(1)?;
        let (need, delta) = arms_effect(then, otherwise)?;
        if (self.produced as isize) < need {
            return Err(ExecutionError::WitnessDataRequired);
        }
        self.produced = (self.produced as isize + delta) as usize;
        Ok(())
    }
}

/// Witness items the path chosen by a complete selector assignment consumes,
/// in the order the script consumes them.
pub fn trace_witness(
    script: &[u8],
    supplied_mask: u16,
    supplied_true_mask: u16,
) -> Result<Vec<WitnessItem>, ExecutionError> {
    let parser = Parser {
        script,
        open: Vec::new(),
        root: Vec::new(),
        next_branch: 0,
        next_key: 0,
    };
    let (program, selector_mask) = parser.parse()?;
    if supplied_mask != selector_mask || supplied_true_mask & !supplied_mask != 0 {
        return Err(ExecutionError::IncompleteSelectors);
    }
    let mut walk = Walk {
        supplied_true_mask,
        produced: 0,
        items: Vec::new(),
    };
    walk.run(&program)?;
    Ok(walk.items)
}

#[cfg(test)]
#[path = "unit-tests/execution.rs"]
mod unit_tests;
