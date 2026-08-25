use crate::{
    contract::{
        commit_reveal, covenant, crowdfund, merkle, oracle, script, seq_commit, shipping_escrow,
        vault, zk,
    },
    error::{Error, Result},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct ContractApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct ScriptApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct CovenantApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct CommitRevealApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct CrowdfundApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct MerkleApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct OracleApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct SequenceCommitApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct ShippingEscrowApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct VaultApi;
#[derive(Clone, Copy, Debug, Default)]
pub struct ZkApi;

impl ContractApi {
    pub(crate) fn new() -> Self {
        Self
    }
    pub fn script(&self) -> ScriptApi {
        ScriptApi
    }
    pub fn covenant(&self) -> CovenantApi {
        CovenantApi
    }
    pub fn commit_reveal(&self) -> CommitRevealApi {
        CommitRevealApi
    }
    pub fn crowdfund(&self) -> CrowdfundApi {
        CrowdfundApi
    }
    pub fn merkle(&self) -> MerkleApi {
        MerkleApi
    }
    pub fn oracle(&self) -> OracleApi {
        OracleApi
    }
    pub fn sequence_commit(&self) -> SequenceCommitApi {
        SequenceCommitApi
    }
    pub fn shipping_escrow(&self) -> ShippingEscrowApi {
        ShippingEscrowApi
    }
    pub fn vault(&self) -> VaultApi {
        VaultApi
    }
    pub fn zk(&self) -> ZkApi {
        ZkApi
    }
}

impl ScriptApi {
    pub fn p2sh_address(&self, redeem_script: &[u8], prefix: &str) -> Result<String> {
        script::p2sh::script_to_address(redeem_script, prefix).map_err(Error::Contract)
    }
    pub fn cltv_locktime(&self, script_bytes: &[u8]) -> Result<Option<u64>> {
        script::extract_cltv_locktime(script_bytes).map_err(Error::Contract)
    }

    pub fn csv_sequence(&self, script_bytes: &[u8]) -> Result<Option<u64>> {
        script::extract_csv_sequence(script_bytes).map_err(Error::Contract)
    }
}

impl CovenantApi {
    pub fn dms(&self, owner: &[u8; 32], heir: &[u8; 32], inactivity_daa: u64) -> Vec<u8> {
        covenant::build_dms_csv_script(owner, heir, inactivity_daa)
    }
    pub fn private_swap(
        &self,
        owner: &[u8; 32],
        claimer: &[u8; 32],
        claimer_spk: &[u8],
        refund_daa: u64,
        salt: &[u8; 16],
    ) -> Result<Vec<u8>> {
        covenant::build_private_swap_script(owner, claimer, claimer_spk, refund_daa, salt)
            .map_err(Error::Contract)
    }
    pub fn piggy_bank(
        &self,
        owner: &[u8; 32],
        threshold_sompi: u64,
        deadline_daa: u64,
        salt: &[u8; 8],
    ) -> Vec<u8> {
        covenant::build_piggy_bank_script(owner, threshold_sompi, deadline_daa, salt)
    }
    pub fn timelocked_savings(
        &self,
        first: &[u8; 32],
        second: &[u8; 32],
        locktime_daa: u64,
    ) -> Vec<u8> {
        covenant::build_timelocked_savings_script(first, second, locktime_daa)
    }
    pub fn payjoin(
        &self,
        owner: &[u8; 32],
        beneficiary: &[u8; 32],
        locktime_daa: u64,
        min_inputs: u64,
        min_outputs: u64,
    ) -> Vec<u8> {
        covenant::build_payjoin_covenant_script(
            owner,
            beneficiary,
            locktime_daa,
            min_inputs,
            min_outputs,
        )
    }
}

impl CommitRevealApi {
    pub fn build(&self, owner: &[u8; 32], commitment: &[u8; 32], locktime_daa: u64) -> Vec<u8> {
        commit_reveal::build_commit_reveal_script(owner, commitment, locktime_daa)
    }
}

impl CrowdfundApi {
    pub fn campaign_id(
        &self,
        goal_sompi: u64,
        locktime_daa: u64,
        verifying_key_hash: &[u8; 32],
        organizer_spk: &[u8],
    ) -> [u8; 32] {
        crowdfund::crowdfund_campaign_id(
            goal_sompi,
            locktime_daa,
            verifying_key_hash,
            organizer_spk,
        )
    }
    pub fn redeem_script(&self, request: crowdfund::CrowdfundScript<'_>) -> Result<Vec<u8>> {
        crowdfund::crowdfund_redeem_script(request).map_err(Error::Contract)
    }
}

impl MerkleApi {
    pub fn root(&self, leaves: &[Vec<u8>]) -> [u8; 32] {
        merkle::compute_merkle_root(leaves)
    }
    pub fn proof(&self, leaves: &[Vec<u8>], leaf_index: usize) -> Vec<([u8; 32], u8)> {
        merkle::generate_merkle_proof(leaves, leaf_index)
    }
}

impl OracleApi {
    pub fn heartbeat_script(&self) -> Vec<u8> {
        oracle::build_oracle_mb_heartbeat_script()
    }
    pub fn heartbeat_sig_script(&self, redeem: &[u8]) -> Vec<u8> {
        oracle::build_oracle_mb_heartbeat_sig_script(redeem)
    }
    pub fn consumer_sig_script(&self, redeem: &[u8]) -> Vec<u8> {
        oracle::build_oracle_mb_consumer_sig_script(redeem)
    }
}

impl SequenceCommitApi {
    #[must_use]
    pub fn stealth_proof(
        &self,
        ephemeral_public_key: &[u8; 32],
        view_tag: u8,
    ) -> seq_commit::SequenceCommitProof {
        seq_commit::stealth_proof(ephemeral_public_key, view_tag)
    }
}

impl ShippingEscrowApi {
    pub fn build(
        &self,
        request: shipping_escrow::ShippingEscrowScriptRequest<'_>,
    ) -> Result<Vec<u8>> {
        shipping_escrow::build_ship_escrow_script(request).map_err(Error::Contract)
    }
}

impl VaultApi {
    pub fn tagged(&self, owner: &[u8; 32]) -> Vec<u8> {
        vault::build_tagged_vault_script(owner)
    }
    pub fn split(&self, owner: &[u8; 32]) -> Vec<u8> {
        vault::build_split_vault_script(owner)
    }
    pub fn covenant_id(
        &self,
        prev_txid: &[u8; 32],
        prev_index: u32,
        outputs: &[(u32, u64, u16, &[u8])],
    ) -> [u8; 32] {
        vault::compute_covenant_id(prev_txid, prev_index, outputs)
    }
}

impl ZkApi {
    pub fn trusted_setup(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        zk::crowdfund_trusted_setup().map_err(Error::Contract)
    }
    pub fn prove_crowdfund(
        &self,
        proving_key: &[u8],
        amounts_sompi: &[u64],
    ) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        zk::crowdfund_generate_proof(proving_key, amounts_sompi).map_err(Error::Contract)
    }
    pub fn verify(&self, verifying_key: &[u8], proof: &[u8], public_input: &[u8]) -> Result<bool> {
        zk::verify_proof(verifying_key, proof, public_input).map_err(Error::Contract)
    }
}
