#[cfg(feature = "std")]
pub(crate) mod covenant;
pub mod model;
pub mod planning;
#[cfg(feature = "std")]
pub(crate) mod pskb;
#[cfg(feature = "std")]
pub mod selection;
#[cfg(feature = "std")]
pub use covenant::{
    build as build_covenant, build_with_binding as build_covenant_with_binding,
    CovenantBuildRequest, CovenantDustPolicy, CovenantEncoding, KIP9_MIN_CHANGE_SOMPI,
};
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
    MultisigTransactionRequest, MULTISIG_BRANCH_SCAN_DEPTH,
};
#[cfg(feature = "std")]
pub use standard::{
    create_consolidation, create_pskb_with_utxos, create_send, create_send_limited,
    create_send_selected, create_send_with_payload,
};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
