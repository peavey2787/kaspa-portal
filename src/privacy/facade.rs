use crate::{
    error::{Error, Result},
    privacy::stealth,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct PrivacyApi;

#[derive(Clone, Copy, Debug, Default)]
pub struct StealthApi;

impl PrivacyApi {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn stealth(&self) -> StealthApi {
        StealthApi
    }
}

impl StealthApi {
    pub fn generate_payment(
        &self,
        metadata: &stealth::StealthMeta,
        entropy: &[u8; 32],
    ) -> Result<stealth::StealthPayment> {
        stealth::generate_stealth_payment(metadata, entropy).map_err(Error::Privacy)
    }

    pub fn announcement_address(&self, prefix: &str) -> String {
        stealth::announcement_address(prefix)
    }

    pub fn decode_metadata(&self, value: &str) -> Result<stealth::StealthMeta> {
        stealth::decode_stealth_meta(value).map_err(Error::Privacy)
    }

    pub fn derive_metadata(&self, kpub: &str) -> Result<stealth::StealthMeta> {
        stealth::derive_stealth_meta_from_kpub(kpub).map_err(Error::Privacy)
    }

    pub fn encode_metadata(&self, value: &stealth::StealthMeta) -> String {
        stealth::encode_stealth_meta(value)
    }

    pub fn scan_raw_for_preimage(&self, raw: &[u8], transaction_id: &[u8]) -> Option<Vec<u8>> {
        stealth::scanner::scan_raw_for_preimage(raw, transaction_id)
    }
}
