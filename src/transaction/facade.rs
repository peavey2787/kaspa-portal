use crate::{
    chain::utxo::UtxoEntry,
    error::{Error, Result},
    network::client::NetworkClient,
    primitives::numeric::ceil_to_u64,
    transaction::{
        builder,
        consensus::ConsensusTransaction,
        interchange::{kspt, pskt},
        model::{SigHashType, Transaction},
    },
    wallet::account::derivation::WalletData,
};

#[derive(Clone)]
pub struct TransactionApi {
    client: Option<NetworkClient>,
}

impl TransactionApi {
    pub(crate) fn new(client: Option<NetworkClient>) -> Self {
        Self { client }
    }

    pub fn pskb(&self) -> builder::PskbApi {
        builder::PskbApi::new()
    }

    pub async fn plan_send(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String> {
        builder::create_send(wallet, destination, amount, fee, self.client()?)
            .await
            .map_err(Error::Transaction)
    }

    pub async fn plan_send_with_payload(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        payload: &[u8],
    ) -> Result<String> {
        builder::create_send_with_payload(wallet, destination, amount, fee, payload, self.client()?)
            .await
            .map_err(Error::Transaction)
    }

    pub async fn plan_selected_send(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        indices: &[usize],
    ) -> Result<String> {
        builder::create_send_selected(wallet, destination, amount, fee, indices, self.client()?)
            .await
            .map_err(Error::Transaction)
    }

    pub async fn plan_consolidation(&self, wallet: &WalletData, fee: u64) -> Result<String> {
        builder::create_consolidation(wallet, fee, self.client()?)
            .await
            .map_err(Error::Transaction)
    }

    pub async fn scan_multisig_branch(
        &self,
        descriptor_text: &str,
        cosigner: u32,
        depth: u32,
        prefix: &str,
    ) -> Result<String> {
        builder::scan_multisig_branch(descriptor_text, cosigner, depth, self.client()?, prefix)
            .await
            .map_err(Error::Transaction)
    }

    pub async fn plan_multisig_consolidation(
        &self,
        request: builder::MultisigConsolidationRequest<'_>,
    ) -> Result<String> {
        builder::create_multisig_consolidation(self.client()?, &request)
            .await
            .map_err(Error::Transaction)
    }

    /// Plan a covenant transaction using the hardened typed covenant builder.
    pub async fn plan_covenant(
        &self,
        request: builder::CovenantBuildRequest<'_>,
    ) -> Result<String> {
        builder::covenant::build(self.client()?, request)
            .await
            .map_err(Error::Transaction)
    }

    /// Plan a covenant transaction and return its bound genesis covenant ID when present.
    pub async fn plan_covenant_with_binding(
        &self,
        request: builder::CovenantBuildRequest<'_>,
    ) -> Result<(String, Option<[u8; 32]>)> {
        builder::covenant::build_with_binding(self.client()?, request)
            .await
            .map_err(Error::Transaction)
    }

    pub fn plan_from_utxos(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        utxos: Vec<UtxoEntry>,
    ) -> Result<String> {
        builder::create_pskb_with_utxos(wallet, destination, amount, fee, utxos)
            .map_err(Error::Transaction)
    }

    /// Plan a payment from KIP-22 coins with change to the KIP-22 key `change_xonly`.
    pub fn plan_kip22_payment(
        &self,
        coins: &[builder::kip22::Kip22Coin],
        destination: &str,
        amount: u64,
        fee: u64,
        change_xonly: &[u8; 32],
    ) -> Result<String> {
        crate::primitives::address::address_to_script_pubkey(destination)
            .and_then(|script| {
                builder::kip22::encode_payment(coins, &script, amount, fee, change_xonly)
            })
            .map_err(Error::Transaction)
    }

    /// Replace the transaction payload on an existing PSKB wire.
    pub fn set_payload(&self, wire_hex: &str, payload: &[u8]) -> Result<String> {
        pskt::set_payload(wire_hex, payload).map_err(Error::Transaction)
    }

    /// Set subnetwork, gas, transaction version, and payload on an existing PSKB wire.
    pub fn set_tx_lane(
        &self,
        wire_hex: &str,
        subnetwork_id_hex: &str,
        gas: u64,
        tx_version: u16,
        payload: &[u8],
    ) -> Result<String> {
        pskt::set_tx_lane(wire_hex, subnetwork_id_hex, gas, tx_version, payload)
            .map_err(Error::Transaction)
    }

    /// Analyze a signed/finalizable PSKB using the node's normal fee estimate when available.
    pub async fn analyze(
        &self,
        wire_hex: &str,
    ) -> Result<crate::transaction::mass::TransactionAnalysis> {
        let fee_rate = match &self.client {
            Some(client) => crate::network::queries::fees::get(client)
                .await
                .ok()
                .and_then(|estimate| ceil_to_u64(estimate.normal_sompi_per_gram))
                .unwrap_or(crate::transaction::mass::MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM),
            None => crate::transaction::mass::MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM,
        };
        self.analyze_with_fee_rate(wire_hex, fee_rate)
    }

    /// Analyze a signed/finalizable PSKB using an explicit sompi-per-gram fee rate.
    pub fn analyze_with_fee_rate(
        &self,
        wire_hex: &str,
        fee_rate_sompi_per_gram: u64,
    ) -> Result<crate::transaction::mass::TransactionAnalysis> {
        verify_for_broadcast(wire_hex)
            .and_then(|verified| {
                crate::transaction::mass::analyze_verified(&verified, fee_rate_sompi_per_gram)
            })
            .map_err(Error::Transaction)
    }

    pub fn review(&self, wire_hex: &str, network_prefix: &str) -> Result<pskt::PsktSummary> {
        pskt::parse_summary(wire_hex, network_prefix).map_err(Error::Transaction)
    }

    pub fn finalize(&self, wire_hex: &str) -> Result<ConsensusTransaction> {
        verify_for_broadcast(wire_hex)
            .and_then(|verified| verified.to_consensus())
            .map_err(Error::Transaction)
    }

    pub fn sign_compact_kspt(
        &self,
        wire: &[u8],
        private_key: &[u8; 32],
        sighash_type: SigHashType,
    ) -> Result<kspt::SignedResponse> {
        let transaction = parse_compact_transaction(wire)?;
        kspt::sign_transaction(&transaction, private_key, sighash_type)
            .map_err(|error| Error::Transaction(format!("KSPT signing failed: {error:?}")))
    }

    pub fn sign_compact_kspt_with_entropy(
        &self,
        wire: &[u8],
        private_key: &[u8; 32],
        sighash_type: SigHashType,
        signing_entropy: &[u8; 32],
    ) -> Result<kspt::SignedResponse> {
        let transaction = parse_compact_transaction(wire)?;
        kspt::sign_transaction_with_entropy(
            &transaction,
            private_key,
            sighash_type,
            signing_entropy,
        )
        .map_err(|error| Error::Transaction(format!("KSPT signing failed: {error:?}")))
    }

    /// Stamp a contract-produced sequence-commit proof onto a PSKB wire value.
    pub fn apply_sequence_commit_proof(
        &self,
        wire_hex: &str,
        proof: &crate::contract::seq_commit::SequenceCommitProof,
    ) -> Result<String> {
        pskt::set_tx_lane(
            wire_hex,
            proof.subnetwork_id_hex,
            proof.gas,
            proof.transaction_version,
            &proof.payload,
        )
        .map_err(Error::Transaction)
    }

    pub async fn broadcast(&self, transaction: &ConsensusTransaction) -> Result<String> {
        crate::transaction::broadcast::submit(self.client()?, transaction)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }

    /// Broadcast `transaction` in place of the mempool transaction it
    /// double-spends; the node requires it to pay a higher feerate.
    pub async fn broadcast_replacement(
        &self,
        transaction: &ConsensusTransaction,
    ) -> Result<String> {
        crate::transaction::broadcast::submit_replacement(self.client()?, transaction)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }

    fn client(&self) -> Result<&NetworkClient> {
        self.client.as_ref().ok_or_else(|| {
            Error::Config("this transaction operation requires a configured Kaspa endpoint".into())
        })
    }
}

fn parse_compact_transaction(wire: &[u8]) -> Result<Transaction> {
    kspt::decode_compact_kspt(wire)
        .map_err(|error| Error::Transaction(format!("KSPT parse failed: {error:?}")))
}

fn verify_for_broadcast(
    wire_hex: &str,
) -> core::result::Result<pskt::pipeline::VerifiedTransaction, String> {
    pskt::pipeline::verify_for_broadcast(wire_hex, kspt::wire::Limits::grammar())
}

#[cfg(test)]
#[path = "unit_tests/facade.rs"]
mod unit_tests;
