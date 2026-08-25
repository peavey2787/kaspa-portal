use super::{CovenantInputPolicy, PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan};
use crate::chain::utxo::UtxoEntry;
use core::fmt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Minimum economically useful continuation under the current KIP-9 storage-mass rules.
pub const MIN_THREAD_CONTINUATION_SOMPI: u64 = 10_000_000;
/// Contract-family differences for the shared single-thread withdrawal/top-up flow.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalThreadPolicy {
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    withdrawal_lock_time: Option<u64>,
    withdrawal_branch: Option<Value>,
    topup_branch: Option<Value>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    topup_sequence: u64,
}
impl GlobalThreadPolicy {
    #[must_use]
    pub fn allowance(cltv_lock_time: u64) -> Self {
        Self {
            withdrawal_lock_time: (cltv_lock_time > 0).then_some(cltv_lock_time),
            withdrawal_branch: Some(Value::from("beneficiary")),
            topup_branch: Some(Value::from("owner")),
            topup_sequence: 0,
        }
    }
    #[must_use]
    pub fn spending_limit() -> Self {
        Self {
            withdrawal_lock_time: Some(0),
            withdrawal_branch: Some(Value::Null),
            topup_branch: Some(Value::Null),
            topup_sequence: 0,
        }
    }

    #[must_use]
    pub fn spending_limit_topup(csv_sequence: u64) -> Self {
        let mut policy = Self::spending_limit();
        policy.topup_sequence = csv_sequence;
        policy
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalThreadPlanError {
    BalanceTooLow { total: u64, fee: u64 },
    WithdrawalNotAboveFee { withdrawal: u64, fee: u64 },
    ContinuationTooSmall { continuation: u64 },
    ArithmeticOverflow { operation: &'static str },
    SelectedFundsTooLow { selected_total: u64, fee: u64 },
}
impl fmt::Display for GlobalThreadPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BalanceTooLow { total, fee } =>
                write!(formatter, "Balance {total} too low to cover fee {fee}"),
            Self::WithdrawalNotAboveFee { withdrawal, fee } =>
                write!(formatter, "Withdrawal {withdrawal} must be greater than fee {fee}"),
            Self::ArithmeticOverflow { operation } =>
                write!(formatter, "Global-thread monetary arithmetic overflow while {operation}"),
            Self::ContinuationTooSmall { continuation } => write!(
                formatter,
                "Continuation {} sompi ({:.4} KAS) is too small. Leave at least 0.1 KAS on the thread, or close it by withdrawing the whole balance (allowed only when balance <= cap).",
                continuation,
                *continuation as f64 / 1e8
            ),
            Self::SelectedFundsTooLow { selected_total, fee } => write!(
                formatter, "Selected wallet funds {selected_total} must exceed fee {fee} to add to the thread"
            ),
        }
    }
}
fn checked_utxo_total(
    utxos: &[UtxoEntry],
    operation: &'static str,
) -> Result<u64, GlobalThreadPlanError> {
    utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or(GlobalThreadPlanError::ArithmeticOverflow { operation })
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalThreadWithdrawalPlan {
    pub plan: PskbPlan,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub total: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub user_receives: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub continuation: u64,
    pub is_close: bool,
}
pub struct GlobalThreadWithdrawalRequest<'a> {
    pub thread_utxos: &'a [UtxoEntry],
    pub covenant_script_public_key: &'a [u8],
    pub destination_script_public_key: &'a [u8],
    pub redeem_script: &'a [u8],
    pub covenant_id: &'a [u8; 32],
    pub withdrawal: u64,
    pub fee: u64,
    pub csv_sequence: u64,
    pub policy: &'a GlobalThreadPolicy,
}
pub fn plan_global_thread_withdrawal(
    request: GlobalThreadWithdrawalRequest<'_>,
) -> Result<GlobalThreadWithdrawalPlan, GlobalThreadPlanError> {
    let thread_utxos = request.thread_utxos;
    let total = checked_utxo_total(thread_utxos, "summing thread UTXOs")?;
    let (is_close, continuation, user_receives) =
        withdrawal_amounts(total, request.withdrawal, request.fee)?;
    let inputs = withdrawal_inputs(&request);
    let outputs = withdrawal_outputs(&request, is_close, continuation, user_receives);
    Ok(GlobalThreadWithdrawalPlan {
        plan: withdrawal_plan(&request, inputs, outputs),
        total,
        user_receives,
        continuation,
        is_close,
    })
}
fn withdrawal_amounts(
    total: u64,
    withdrawal: u64,
    fee: u64,
) -> Result<(bool, u64, u64), GlobalThreadPlanError> {
    validate_withdrawal_balances(total, withdrawal, fee)?;
    let is_close = total <= withdrawal;
    let continuation = continuation_amount(total, withdrawal, is_close)?;
    validate_continuation(continuation, is_close)?;
    let user_receives = receive_amount(total, withdrawal, fee, is_close)?;
    Ok((is_close, continuation, user_receives))
}

fn validate_withdrawal_balances(
    total: u64,
    withdrawal: u64,
    fee: u64,
) -> Result<(), GlobalThreadPlanError> {
    if total <= fee {
        return Err(GlobalThreadPlanError::BalanceTooLow { total, fee });
    }
    if withdrawal <= fee {
        return Err(GlobalThreadPlanError::WithdrawalNotAboveFee { withdrawal, fee });
    }
    Ok(())
}
fn continuation_amount(
    total: u64,
    withdrawal: u64,
    is_close: bool,
) -> Result<u64, GlobalThreadPlanError> {
    if is_close {
        return Ok(0);
    }
    total
        .checked_sub(withdrawal)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting withdrawal from thread balance",
        })
}
fn receive_amount(
    total: u64,
    withdrawal: u64,
    fee: u64,
    is_close: bool,
) -> Result<u64, GlobalThreadPlanError> {
    let source = if is_close { total } else { withdrawal };
    source
        .checked_sub(fee)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting fee from withdrawal value",
        })
}
fn validate_continuation(continuation: u64, is_close: bool) -> Result<(), GlobalThreadPlanError> {
    if !is_close && continuation < MIN_THREAD_CONTINUATION_SOMPI {
        Err(GlobalThreadPlanError::ContinuationTooSmall { continuation })
    } else {
        Ok(())
    }
}

fn withdrawal_inputs(request: &GlobalThreadWithdrawalRequest<'_>) -> Vec<PskbInputPlan> {
    request
        .thread_utxos
        .iter()
        .cloned()
        .map(|utxo| {
            PskbInputPlan::covenant(
                utxo,
                request.covenant_script_public_key,
                request.redeem_script,
                CovenantInputPolicy {
                    sequence: request.csv_sequence,
                    sig_op_count: 1,
                    minimum_signatures: 1,
                    proprietaries: Value::Array(Vec::new()),
                    min_time: Some(0),
                },
            )
        })
        .collect()
}
fn withdrawal_outputs(
    request: &GlobalThreadWithdrawalRequest<'_>,
    is_close: bool,
    continuation: u64,
    user_receives: u64,
) -> Vec<PskbOutputPlan> {
    let mut outputs = Vec::with_capacity(if is_close { 1 } else { 2 });
    if !is_close {
        outputs.push(
            PskbOutputPlan::plain(continuation, request.covenant_script_public_key)
                .with_binding_field(json!({
                    "authorizingInput": 0,
                    "covenantId": hex::encode(request.covenant_id),
                })),
        );
    }
    outputs.push(
        PskbOutputPlan::plain(user_receives, request.destination_script_public_key)
            .with_binding_field(Value::Null),
    );
    outputs
}
fn withdrawal_plan(
    request: &GlobalThreadWithdrawalRequest<'_>,
    inputs: Vec<PskbInputPlan>,
    outputs: Vec<PskbOutputPlan>,
) -> PskbPlan {
    PskbPlan {
        global: PskbGlobalPlan {
            tx_version: 1,
            fallback_lock_time: request.policy.withdrawal_lock_time,
            covenant_branch: request.policy.withdrawal_branch.clone(),
            proprietaries: Value::Array(Vec::new()),
            transaction_payload: None,
        },
        inputs,
        outputs,
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalThreadTopupPlan {
    pub plan: PskbPlan,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub wallet_total: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub continuation: u64,
}

pub struct GlobalThreadTopupRequest<'a> {
    pub thread_utxo: UtxoEntry,
    pub wallet_utxos: &'a [UtxoEntry],
    pub covenant_script_public_key: &'a [u8],
    pub redeem_script: &'a [u8],
    pub covenant_id: &'a [u8; 32],
    pub fee: u64,
    pub policy: &'a GlobalThreadPolicy,
}
pub fn plan_global_thread_topup(
    request: GlobalThreadTopupRequest<'_>,
) -> Result<GlobalThreadTopupPlan, GlobalThreadPlanError> {
    let GlobalThreadTopupRequest {
        thread_utxo,
        wallet_utxos,
        covenant_script_public_key,
        redeem_script,
        covenant_id,
        fee,
        policy,
    } = request;
    let wallet_total = checked_utxo_total(wallet_utxos, "summing wallet top-up UTXOs")?;
    if wallet_total <= fee {
        return Err(GlobalThreadPlanError::SelectedFundsTooLow {
            selected_total: wallet_total,
            fee,
        });
    }
    let thread_amount = thread_utxo.amount;
    let continuation = thread_amount
        .checked_add(wallet_total)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "adding thread and wallet balances",
        })?
        .checked_sub(fee)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting fee from top-up continuation",
        })?;
    let mut inputs = Vec::with_capacity(1 + wallet_utxos.len());
    inputs.push(PskbInputPlan::covenant(
        thread_utxo,
        covenant_script_public_key,
        redeem_script,
        CovenantInputPolicy {
            sequence: policy.topup_sequence,
            sig_op_count: 1,
            minimum_signatures: 1,
            proprietaries: Value::Array(Vec::new()),
            min_time: Some(0),
        },
    ));
    inputs.extend(wallet_utxos.iter().cloned().map(|utxo| {
        let source_script_public_key = utxo.script_public_key.clone();
        let block_daa_score = utxo.block_daa_score;
        let mut input =
            PskbInputPlan::p2pk(utxo, &source_script_public_key, Value::Array(Vec::new()));
        input.block_daa_score = block_daa_score;
        input
    }));
    let outputs = vec![
        PskbOutputPlan::plain(continuation, covenant_script_public_key).with_binding_field(json!({
            "authorizingInput": 0,
            "covenantId": hex::encode(covenant_id),
        })),
    ];

    Ok(GlobalThreadTopupPlan {
        plan: PskbPlan {
            global: PskbGlobalPlan {
                tx_version: 1,
                fallback_lock_time: Some(0),
                covenant_branch: policy.topup_branch.clone(),
                proprietaries: Value::Array(Vec::new()),
                transaction_payload: None,
            },
            inputs,
            outputs,
        },
        wallet_total,
        continuation,
    })
}
