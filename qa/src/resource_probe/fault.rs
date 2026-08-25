use std::hint::black_box;

use kaspa_portal::{
    network::{client::NetworkClient, wrpc::operation::Operation},
    platform::native::websocket::NativeWebSocketTransport,
};

use crate::fault_server::{FaultMode, FaultServer};

pub async fn run(iteration: usize) -> Result<(), String> {
    let server = FaultServer::bind().await?;
    let endpoint = server.endpoint()?;
    let task = tokio::spawn(server.serve());
    let modes = [
        FaultMode::Malformed,
        FaultMode::MismatchedId,
        FaultMode::MismatchedOperation,
        FaultMode::RemoteError,
        FaultMode::CloseBeforeResponse,
        FaultMode::TextBeforeBinary,
    ];
    let mode = modes[iteration % modes.len()];
    let failed = call(&endpoint, mode).await.is_err();
    if !failed {
        task.abort();
        return Err(format!("fault mode {mode:?} unexpectedly succeeded"));
    }
    let recovered = call(&endpoint, FaultMode::Valid).await?;
    if recovered != b"fault-ok" {
        task.abort();
        return Err("fault transport recovery returned unexpected payload".into());
    }
    task.abort();
    let _ = task.await;
    black_box((failed, recovered));
    Ok(())
}

async fn call(endpoint: &str, mode: FaultMode) -> Result<Vec<u8>, String> {
    let transport = NativeWebSocketTransport::new(endpoint).map_err(|error| error.to_string())?;
    NetworkClient::new(transport)
        .call(Operation::GetBlockDagInfo, &[mode as u8])
        .await
        .map_err(|error| error.to_string())
}
