//! Typed, template-bound witness plans for the specialized covenant families
//! that are currently exposed by Companion transaction builders.
//!
//! Proprietary metadata is never allowed to select a branch on its own. A route
//! is accepted only when (1) the redeem script exactly matches the recognized
//! template, (2) `covenantExecution` supplies every structural selector, (3)
//! those selectors choose the route's branch, (4) the already-verified
//! transaction signature is bound to that branch, and (5) route-specific proof
//! material validates against commitments embedded in the redeem script.

use blake2b_simd::Params;
use k256::schnorr::{Signature as K256Signature, VerifyingKey};
use serde_json::{Map, Value};

use super::compact::{Input, Signature, SpecializedRoute, SpecializedWitness};
use crate::contract::script::opcode::{
    OP_0, OP_1, OP_BLAKE2B, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIGFROMSTACK,
    OP_CHECKSIGVERIFY, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_GREATERTHANOREQUAL,
    OP_IF, OP_LESSTHANOREQUAL, OP_NUMEQUALVERIFY, OP_SUB, OP_SWAP, OP_TX_INPUT_AMOUNT,
    OP_TX_INPUT_COUNT, OP_TX_OUTPUT_AMOUNT, OP_TX_OUTPUT_COUNT, OP_TX_OUTPUT_SPK, OP_VERIFY,
};
mod claims;
mod merkle_proof;
mod routes;
mod templates;
pub(crate) use claims::*;
pub(crate) use merkle_proof::*;
pub(crate) use routes::*;
pub(crate) use templates::*;

const PRIVATE_SWAP_MAX_FEE_SOMPI: u64 = 500_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteKind {
    PrivateSwap,
    OracleV1,
    CommitReveal,
    Merkle,
}
