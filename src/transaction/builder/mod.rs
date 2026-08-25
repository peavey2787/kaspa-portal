pub(crate) mod covenant;
pub mod model;
pub mod planning;
pub(crate) mod pskb;
pub mod selection;
pub use covenant::{CovenantBuildRequest, CovenantEncoding};
pub use pskb::{
    CovenantInputPolicy, GlobalThreadPlanError, GlobalThreadPolicy, GlobalThreadTopupPlan,
    GlobalThreadTopupRequest, GlobalThreadWithdrawalPlan, GlobalThreadWithdrawalRequest, PskbApi,
    PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan, SweepInputPolicy,
};

mod multisig;
mod standard;

pub use multisig::{
    create as create_multisig, create_consolidation as create_multisig_consolidation,
    scan_branch as scan_multisig_branch, MultisigConsolidationRequest, MultisigSelection,
    MultisigTransactionRequest,
};
pub use standard::{
    create_consolidation, create_pskb_with_utxos, create_send, create_send_limited,
    create_send_selected,
};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
