pub(crate) mod script;

pub use script::{
    crowdfund_campaign_id, crowdfund_redeem_script, CrowdfundScript, CROWDFUND_MAX_CONTRIBUTORS,
    CROWDFUND_MAX_SWEEP_FEE_SOMPI, CROWDFUND_MAX_TX_INPUTS, CROWDFUND_SIG_OP_COUNT,
};
