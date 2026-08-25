#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Degraded,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkHealth {
    pub status: ConnectionStatus,
    pub endpoint: String,
    pub virtual_daa_score: Option<u64>,
}
