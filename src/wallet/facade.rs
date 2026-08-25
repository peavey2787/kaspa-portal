use crate::{
    chain::{utxo::UtxoEntry, ChainApi},
    error::{Error, Result},
    wallet::{
        account::{
            balance::{self, BalanceInfo},
            derivation::{self, WalletData},
        },
        mnemonic::bip39,
    },
};

#[derive(Clone)]
pub struct WalletApi {
    chain: Option<ChainApi>,
    prefix: String,
}

impl WalletApi {
    pub(crate) fn new(chain: Option<ChainApi>, prefix: impl Into<String>) -> Self {
        Self {
            chain,
            prefix: prefix.into(),
        }
    }

    pub fn import_kpub(&self, kpub: &str) -> Result<WalletData> {
        derivation::import_kpub(kpub, &self.prefix).map_err(Error::Wallet)
    }

    pub fn import_kpub_raw(&self, payload: &[u8]) -> Result<WalletData> {
        derivation::import_kpub_raw(payload, &self.prefix).map_err(Error::Wallet)
    }

    pub fn extend_addresses(
        &self,
        wallet: &WalletData,
        receive: u32,
        change: u32,
    ) -> Result<WalletData> {
        derivation::extend_addresses(wallet, receive, change, &self.prefix).map_err(Error::Wallet)
    }

    pub async fn utxos(&self, wallet: &WalletData) -> Result<Vec<UtxoEntry>> {
        let chain = self.chain()?;
        let addresses = wallet
            .receive_addresses
            .iter()
            .chain(wallet.change_addresses.iter())
            .cloned()
            .collect::<Vec<_>>();
        chain.utxos_many(&addresses).await
    }

    pub async fn balance(&self, wallet: &WalletData) -> Result<BalanceInfo> {
        let utxos = self.utxos(wallet).await?;
        balance::summarize_balance(wallet, &utxos).map_err(Error::Wallet)
    }

    pub fn mnemonic_12_from_entropy(&self, entropy: &[u8; 16]) -> bip39::Mnemonic12 {
        bip39::mnemonic_from_entropy_12(entropy)
    }

    pub fn mnemonic_24_from_entropy(&self, entropy: &[u8; 32]) -> bip39::Mnemonic24 {
        bip39::mnemonic_from_entropy_24(entropy)
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn chain(&self) -> Result<&ChainApi> {
        self.chain.as_ref().ok_or_else(|| {
            Error::Config("this wallet operation requires a configured Kaspa endpoint".into())
        })
    }
}
