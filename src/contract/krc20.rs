//! KRC-20 (Kasplex) token operations carried in a reveal redeem script.
//!
//! A Kasplex reveal spends a P2SH output whose redeem script embeds an
//! envelope after the spending key check:
//! `... OP_0 OP_IF <"kasplex"> [<metadata>...] <json> OP_ENDIF`. The JSON is
//! `{"p":"krc-20","op":"transfer","tick":"NACHO","amt":"100000000",...}`.
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use serde::Deserialize;

use crate::primitives::{
    opcode::{OP_0, OP_ENDIF, OP_IF},
    script::elements,
};

const PROTOCOL_TAG: &[u8] = b"kasplex";

/// The KRC-20 operation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Krc20Op {
    Deploy,
    Mint,
    Transfer,
    Other,
}

impl Krc20Op {
    /// Upper-case display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Deploy => "DEPLOY",
            Self::Mint => "MINT",
            Self::Transfer => "TRANSFER",
            Self::Other => "?",
        }
    }
}

/// A KRC-20 operation found in a Kasplex envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Krc20Operation {
    pub op: Krc20Op,
    pub ticker: String,
    pub amount: Option<String>,
    pub recipient: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
    p: String,
    op: String,
    tick: String,
    amt: Option<String>,
    to: Option<String>,
}

/// The KRC-20 operation a reveal redeem script carries, if it is a
/// well-formed Kasplex envelope with KRC-20 JSON.
#[must_use]
pub fn krc20_operation(redeem_script: &[u8]) -> Option<Krc20Operation> {
    let json = envelope_payload(redeem_script)?;
    let envelope: Envelope = serde_json::from_slice(json).ok()?;
    if !envelope.p.eq_ignore_ascii_case("krc-20") || envelope.tick.is_empty() {
        return None;
    }
    let op = match envelope.op.to_ascii_lowercase().as_str() {
        "deploy" => Krc20Op::Deploy,
        "mint" => Krc20Op::Mint,
        "transfer" => Krc20Op::Transfer,
        _ => Krc20Op::Other,
    };
    Some(Krc20Operation {
        op,
        ticker: envelope.tick.to_ascii_uppercase(),
        amount: envelope.amt,
        recipient: envelope.to,
    })
}

/// The last data push of the `OP_0 OP_IF <"kasplex"> ... OP_ENDIF` envelope.
fn envelope_payload(script: &[u8]) -> Option<&[u8]> {
    let items = elements(script).collect::<Vec<_>>();
    let start = items.windows(3).position(|window| {
        window[0].opcode == OP_0 && window[1].opcode == OP_IF && window[2].data == PROTOCOL_TAG
    })?;
    let body = &items[start + 3..];
    let end = body.iter().position(|item| item.opcode == OP_ENDIF)?;
    body[..end]
        .iter()
        .rev()
        .find(|item| item.is_push() && !item.data.is_empty())
        .map(|item| item.data)
}

#[cfg(test)]
#[path = "unit-tests/krc20.rs"]
mod unit_tests;
