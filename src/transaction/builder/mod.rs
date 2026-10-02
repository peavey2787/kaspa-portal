#[cfg(feature = "std")]
pub(crate) mod covenant;
pub mod model;
pub mod planning;
#[cfg(feature = "std")]
pub(crate) mod pskb;
#[cfg(feature = "std")]
pub mod selection;
#[cfg(feature = "std")]
pub use covenant::{CovenantBuildRequest, CovenantEncoding};
#[cfg(feature = "std")]
pub use pskb::{
    CovenantInputPolicy, GlobalThreadPlanError, GlobalThreadPolicy, GlobalThreadTopupPlan,
    GlobalThreadTopupRequest, GlobalThreadWithdrawalPlan, GlobalThreadWithdrawalRequest, PskbApi,
    PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan, SweepInputPolicy,
};

#[cfg(feature = "std")]
mod multisig;
#[cfg(feature = "std")]
mod standard;

#[cfg(feature = "std")]
pub use multisig::{
    create as create_multisig, create_consolidation as create_multisig_consolidation,
    scan_branch as scan_multisig_branch, MultisigConsolidationRequest, MultisigSelection,
    MultisigTransactionRequest,
};
#[cfg(feature = "std")]
pub use standard::{
    create_consolidation, create_pskb_with_utxos, create_send, create_send_limited,
    create_send_selected, create_send_with_payload,
};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
