//! Typed, template-bound witness plans for the specialized covenant families
//! that are currently exposed by Companion transaction builders.
//!
//! Proprietary metadata is never allowed to select a branch on its own. A route
//! is accepted only when (1) the redeem script exactly matches the recognized
//! template, (2) `covenantExecution` supplies every structural selector, (3)
//! those selectors choose the route's branch, (4) the already-verified
//! transaction signature is bound to that branch, and (5) route-specific proof
//! material validates against commitments embedded in the redeem script.

use k256::schnorr::{Signature as K256Signature, VerifyingKey};
use serde_json::{Map, Value};

use super::compact::{Input, Signature, SpecializedRoute, SpecializedWitness};
use crate::contract::script::opcode::{OP_0, OP_1};
mod claims;
mod merkle_proof;
mod routes;
mod templates;
pub(crate) use claims::*;
pub(crate) use merkle_proof::*;
pub(crate) use routes::*;
pub(crate) use templates::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteKind {
    PrivateSwap,
    OracleV1,
    CommitReveal,
    Merkle,
}
