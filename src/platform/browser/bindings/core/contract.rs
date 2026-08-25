use serde::Deserialize;
use wasm_bindgen::prelude::*;

use super::{decimal, js_error};
use crate::contract::{
    crowdfund::CrowdfundScript, shipping_escrow::ShippingEscrowScriptRequest, ContractApi,
};

#[wasm_bindgen(js_name = KaspaContract)]
pub struct WasmContract {
    inner: ContractApi,
}

impl WasmContract {
    pub(crate) fn from_api(inner: ContractApi) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen(js_class = KaspaContract)]
impl WasmContract {
    #[wasm_bindgen(js_name = p2shAddress)]
    pub fn p2sh_address(&self, redeem_script: &[u8], prefix: &str) -> Result<String, JsValue> {
        self.inner
            .script()
            .p2sh_address(redeem_script, prefix)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = cltvLocktime)]
    pub fn cltv_locktime(&self, script: &[u8]) -> Result<JsValue, JsValue> {
        self.inner
            .script()
            .cltv_locktime(script)
            .map(optional_decimal_js)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = csvSequence)]
    pub fn csv_sequence(&self, script: &[u8]) -> Result<JsValue, JsValue> {
        self.inner
            .script()
            .csv_sequence(script)
            .map(optional_decimal_js)
            .map_err(js_error)
    }

    pub fn dms(
        &self,
        owner_hex: &str,
        heir_hex: &str,
        inactivity_daa: &str,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.covenant().dms(
            &fixed32(owner_hex, "owner")?,
            &fixed32(heir_hex, "heir")?,
            decimal(inactivity_daa, "inactivity DAA")?,
        ))
    }

    #[wasm_bindgen(js_name = privateSwap)]
    pub fn private_swap(
        &self,
        owner_hex: &str,
        claimer_hex: &str,
        claimer_spk_hex: &str,
        refund_daa: &str,
        salt_hex: &str,
    ) -> Result<Vec<u8>, JsValue> {
        let claimer_spk = bytes_hex(claimer_spk_hex, "claimer script")?;
        self.inner
            .covenant()
            .private_swap(
                &fixed32(owner_hex, "owner")?,
                &fixed32(claimer_hex, "claimer")?,
                &claimer_spk,
                decimal(refund_daa, "refund DAA")?,
                &fixed16(salt_hex, "private swap salt")?,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = piggyBank)]
    pub fn piggy_bank(
        &self,
        owner_hex: &str,
        threshold_sompi: &str,
        deadline_daa: &str,
        salt_hex: &str,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.covenant().piggy_bank(
            &fixed32(owner_hex, "owner")?,
            decimal(threshold_sompi, "threshold")?,
            decimal(deadline_daa, "deadline DAA")?,
            &fixed8(salt_hex, "piggy-bank salt")?,
        ))
    }

    #[wasm_bindgen(js_name = timelockedSavings)]
    pub fn timelocked_savings(
        &self,
        first_hex: &str,
        second_hex: &str,
        locktime_daa: &str,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.covenant().timelocked_savings(
            &fixed32(first_hex, "first key")?,
            &fixed32(second_hex, "second key")?,
            decimal(locktime_daa, "locktime DAA")?,
        ))
    }

    pub fn payjoin(
        &self,
        owner_hex: &str,
        beneficiary_hex: &str,
        locktime_daa: &str,
        min_inputs: &str,
        min_outputs: &str,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.covenant().payjoin(
            &fixed32(owner_hex, "owner")?,
            &fixed32(beneficiary_hex, "beneficiary")?,
            decimal(locktime_daa, "locktime DAA")?,
            decimal(min_inputs, "minimum inputs")?,
            decimal(min_outputs, "minimum outputs")?,
        ))
    }

    #[wasm_bindgen(js_name = commitReveal)]
    pub fn commit_reveal(
        &self,
        owner_hex: &str,
        commitment_hex: &str,
        locktime_daa: &str,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.commit_reveal().build(
            &fixed32(owner_hex, "owner")?,
            &fixed32(commitment_hex, "commitment")?,
            decimal(locktime_daa, "locktime DAA")?,
        ))
    }

    #[wasm_bindgen(js_name = crowdfundCampaignId)]
    pub fn crowdfund_campaign_id(
        &self,
        goal_sompi: &str,
        locktime_daa: &str,
        verifying_key_hash_hex: &str,
        organizer_spk_hex: &str,
    ) -> Result<String, JsValue> {
        let organizer_spk = bytes_hex(organizer_spk_hex, "organizer script")?;
        Ok(hex::encode(self.inner.crowdfund().campaign_id(
            decimal(goal_sompi, "goal")?,
            decimal(locktime_daa, "locktime DAA")?,
            &fixed32(verifying_key_hash_hex, "verifying key hash")?,
            &organizer_spk,
        )))
    }

    #[wasm_bindgen(js_name = crowdfundRedeemScript)]
    pub fn crowdfund_redeem_script(
        &self,
        contributor_hex: &str,
        goal_sompi: &str,
        locktime_daa: &str,
        verifying_key_hash_hex: &str,
        organizer_spk_hex: &str,
        salt_hex: &str,
    ) -> Result<Vec<u8>, JsValue> {
        let contributor = fixed32(contributor_hex, "contributor")?;
        let verifying_key_hash = fixed32(verifying_key_hash_hex, "verifying key hash")?;
        let organizer_spk = bytes_hex(organizer_spk_hex, "organizer script")?;
        let salt = fixed8(salt_hex, "crowdfund salt")?;
        self.inner
            .crowdfund()
            .redeem_script(CrowdfundScript {
                contributor_pubkey: &contributor,
                goal_sompi: decimal(goal_sompi, "goal")?,
                locktime_daa: decimal(locktime_daa, "locktime DAA")?,
                verifying_key_hash: &verifying_key_hash,
                organizer_output_spk: &organizer_spk,
                salt: &salt,
            })
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = merkleRoot)]
    pub fn merkle_root(&self, leaves_json: &str) -> Result<String, JsValue> {
        let leaves = hex_vec_json(leaves_json, "Merkle leaves")?;
        Ok(hex::encode(self.inner.merkle().root(&leaves)))
    }

    #[wasm_bindgen(js_name = merkleProof)]
    pub fn merkle_proof(&self, leaves_json: &str, leaf_index: u32) -> Result<String, JsValue> {
        let leaves = hex_vec_json(leaves_json, "Merkle leaves")?;
        let index = usize::try_from(leaf_index)
            .map_err(|_| JsValue::from_str("leaf index does not fit this platform"))?;
        let proof = self
            .inner
            .merkle()
            .proof(&leaves, index)
            .into_iter()
            .map(|(hash, direction)| {
                serde_json::json!({"hash": hex::encode(hash), "direction": direction})
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&proof).map_err(json_error)
    }

    #[wasm_bindgen(js_name = oracleHeartbeatScript)]
    pub fn oracle_heartbeat_script(&self) -> Vec<u8> {
        self.inner.oracle().heartbeat_script()
    }

    #[wasm_bindgen(js_name = oracleHeartbeatSigScript)]
    pub fn oracle_heartbeat_sig_script(&self, redeem: &[u8]) -> Vec<u8> {
        self.inner.oracle().heartbeat_sig_script(redeem)
    }

    #[wasm_bindgen(js_name = oracleConsumerSigScript)]
    pub fn oracle_consumer_sig_script(&self, redeem: &[u8]) -> Vec<u8> {
        self.inner.oracle().consumer_sig_script(redeem)
    }

    #[wasm_bindgen(js_name = sequenceCommitStealthProof)]
    pub fn sequence_commit_stealth_proof(
        &self,
        ephemeral_public_key_hex: &str,
        view_tag: u8,
    ) -> Result<String, JsValue> {
        let proof = self.inner.sequence_commit().stealth_proof(
            &fixed32(ephemeral_public_key_hex, "ephemeral public key")?,
            view_tag,
        );
        Ok(serde_json::json!({
            "subnetworkId": proof.subnetwork_id_hex,
            "gas": proof.gas.to_string(),
            "transactionVersion": proof.transaction_version,
            "payload": hex::encode(proof.payload),
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = shippingEscrow)]
    pub fn shipping_escrow(&self, request_json: &str) -> Result<Vec<u8>, JsValue> {
        let request: BrowserShippingEscrow =
            serde_json::from_str(request_json).map_err(|error| {
                JsValue::from_str(&format!("invalid shipping escrow JSON: {error}"))
            })?;
        let seller = fixed32(&request.seller_pubkey, "seller")?;
        let deliverer = fixed32(&request.deliverer_pubkey, "deliverer")?;
        let buyer = fixed32(&request.buyer_pubkey, "buyer")?;
        let arbiter = fixed32(&request.arbiter_pubkey, "arbiter")?;
        let salt = fixed8(&request.salt, "shipping escrow salt")?;
        self.inner
            .shipping_escrow()
            .build(ShippingEscrowScriptRequest {
                seller_pubkey: &seller,
                deliverer_pubkey: &deliverer,
                buyer_pubkey: &buyer,
                arbiter_pubkey: &arbiter,
                product_sompi: decimal(&request.product_sompi, "product amount")?,
                fee_sompi: decimal(&request.fee_sompi, "fee")?,
                cltv1_deadline: decimal(&request.cltv1_deadline, "first deadline")?,
                cltv2_deadline: decimal(&request.cltv2_deadline, "second deadline")?,
                salt: &salt,
            })
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = taggedVault)]
    pub fn tagged_vault(&self, owner_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.vault().tagged(&fixed32(owner_hex, "owner")?))
    }

    #[wasm_bindgen(js_name = splitVault)]
    pub fn split_vault(&self, owner_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.vault().split(&fixed32(owner_hex, "owner")?))
    }

    #[wasm_bindgen(js_name = covenantId)]
    pub fn covenant_id(
        &self,
        prev_txid_hex: &str,
        prev_index: u32,
        outputs_json: &str,
    ) -> Result<String, JsValue> {
        let outputs: Vec<BrowserVaultOutput> = serde_json::from_str(outputs_json)
            .map_err(|error| JsValue::from_str(&format!("invalid vault outputs JSON: {error}")))?;
        let owned = outputs
            .into_iter()
            .map(|output| {
                Ok((
                    output.index,
                    decimal(&output.amount_sompi, "output amount")?,
                    output.version,
                    bytes_hex(&output.script_hex, "output script")?,
                ))
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
        let refs = owned
            .iter()
            .map(|(index, amount, version, script)| (*index, *amount, *version, script.as_slice()))
            .collect::<Vec<_>>();
        Ok(hex::encode(self.inner.vault().covenant_id(
            &fixed32(prev_txid_hex, "previous transaction id")?,
            prev_index,
            &refs,
        )))
    }

    #[wasm_bindgen(js_name = zkTrustedSetup)]
    pub fn zk_trusted_setup(&self) -> Result<String, JsValue> {
        let (proving_key, verifying_key) = self.inner.zk().trusted_setup().map_err(js_error)?;
        Ok(serde_json::json!({
            "provingKey": hex::encode(proving_key),
            "verifyingKey": hex::encode(verifying_key),
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = zkProveCrowdfund)]
    pub fn zk_prove_crowdfund(
        &self,
        proving_key_hex: &str,
        amounts_json: &str,
    ) -> Result<String, JsValue> {
        let proving_key = bytes_hex(proving_key_hex, "proving key")?;
        let amounts: Vec<String> = serde_json::from_str(amounts_json)
            .map_err(|error| JsValue::from_str(&format!("invalid amount list JSON: {error}")))?;
        let amounts = amounts
            .iter()
            .map(|value| decimal(value, "crowdfund amount"))
            .collect::<Result<Vec<_>, JsValue>>()?;
        let (proof, public_input, total) = self
            .inner
            .zk()
            .prove_crowdfund(&proving_key, &amounts)
            .map_err(js_error)?;
        Ok(serde_json::json!({
            "proof": hex::encode(proof),
            "publicInput": hex::encode(public_input),
            "totalSompi": total.to_string(),
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = zkVerify)]
    pub fn zk_verify(
        &self,
        verifying_key_hex: &str,
        proof_hex: &str,
        public_input_hex: &str,
    ) -> Result<bool, JsValue> {
        self.inner
            .zk()
            .verify(
                &bytes_hex(verifying_key_hex, "verifying key")?,
                &bytes_hex(proof_hex, "proof")?,
                &bytes_hex(public_input_hex, "public input")?,
            )
            .map_err(js_error)
    }
}

fn optional_decimal_js(value: Option<u64>) -> JsValue {
    match value {
        Some(value) => JsValue::from_str(&value.to_string()),
        None => JsValue::NULL,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserShippingEscrow {
    seller_pubkey: String,
    deliverer_pubkey: String,
    buyer_pubkey: String,
    arbiter_pubkey: String,
    product_sompi: String,
    fee_sompi: String,
    cltv1_deadline: String,
    cltv2_deadline: String,
    salt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserVaultOutput {
    index: u32,
    amount_sompi: String,
    version: u16,
    script_hex: String,
}

fn fixed32(value: &str, name: &str) -> Result<[u8; 32], JsValue> {
    fixed(value, name)
}

fn fixed16(value: &str, name: &str) -> Result<[u8; 16], JsValue> {
    fixed(value, name)
}

fn fixed8(value: &str, name: &str) -> Result<[u8; 8], JsValue> {
    fixed(value, name)
}

fn fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N], JsValue> {
    bytes_hex(value, name)?
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{name} must be {N} bytes")))
}

fn bytes_hex(value: &str, name: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(value).map_err(|error| JsValue::from_str(&format!("invalid {name}: {error}")))
}

fn hex_vec_json(value: &str, name: &str) -> Result<Vec<Vec<u8>>, JsValue> {
    let values: Vec<String> = serde_json::from_str(value)
        .map_err(|error| JsValue::from_str(&format!("invalid {name} JSON: {error}")))?;
    values
        .iter()
        .map(|item| bytes_hex(item, name))
        .collect::<Result<Vec<_>, _>>()
}

fn json_error(error: serde_json::Error) -> JsValue {
    JsValue::from_str(&format!("JSON encode failed: {error}"))
}
