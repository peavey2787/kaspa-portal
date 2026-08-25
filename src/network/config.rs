use crate::primitives::NetworkId;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    pub network: NetworkId,
    pub endpoint: String,
    pub timeout_ms: u64,
    pub max_retries: u8,
}
impl NetworkConfig {
    pub fn mainnet(endpoint: impl Into<String>) -> Self {
        Self {
            network: NetworkId::Mainnet,
            endpoint: endpoint.into(),
            timeout_ms: 15_000,
            max_retries: 3,
        }
    }
}
