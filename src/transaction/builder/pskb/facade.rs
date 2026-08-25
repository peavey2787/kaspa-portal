use serde_json::Value;

use crate::{
    chain::utxo::UtxoEntry,
    error::{Error, Result},
};

use super::{
    encoder,
    global_thread::{
        self, GlobalThreadTopupPlan, GlobalThreadTopupRequest, GlobalThreadWithdrawalPlan,
        GlobalThreadWithdrawalRequest,
    },
    sweep::{self, SweepInputPolicy},
    PskbGlobalPlan, PskbPlan,
};

/// High-level facade for typed PSKB planning and canonical wire encoding.
#[derive(Clone, Copy, Debug, Default)]
pub struct PskbApi;

impl PskbApi {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn encode(&self, plan: &PskbPlan) -> Result<String> {
        encoder::encode_wire(plan).map_err(Error::Transaction)
    }

    /// Encode a preassembled PSKT/PSKB document into the canonical PSKB wire envelope.
    pub fn encode_document(&self, document: Value) -> Result<String> {
        encoder::encode_pskt_value(document).map_err(Error::Transaction)
    }

    #[must_use]
    pub fn plan_sweep(
        &self,
        utxos: &[UtxoEntry],
        source_script_public_key: &[u8],
        destination_script_public_key: &[u8],
        send_amount: u64,
        global: PskbGlobalPlan,
        input_policy: &SweepInputPolicy,
    ) -> PskbPlan {
        sweep::plan_sweep(
            utxos,
            source_script_public_key,
            destination_script_public_key,
            send_amount,
            global,
            input_policy,
        )
    }

    pub fn plan_global_thread_withdrawal(
        &self,
        request: GlobalThreadWithdrawalRequest<'_>,
    ) -> Result<GlobalThreadWithdrawalPlan> {
        global_thread::plan_global_thread_withdrawal(request)
            .map_err(|error| Error::Transaction(error.to_string()))
    }

    pub fn plan_global_thread_topup(
        &self,
        request: GlobalThreadTopupRequest<'_>,
    ) -> Result<GlobalThreadTopupPlan> {
        global_thread::plan_global_thread_topup(request)
            .map_err(|error| Error::Transaction(error.to_string()))
    }
}
