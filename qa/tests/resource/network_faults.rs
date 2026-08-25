#[path = "../../src/fault_server/mod.rs"]
mod fault_server;

use kaspa_portal::{
    network::{
        client::NetworkClient,
        error::NetworkError,
        wrpc::operation::Operation,
    },
    platform::native::websocket::NativeWebSocketTransport,
};

use fault_server::{FaultMode, FaultServer};

async fn call(endpoint: &str, mode: FaultMode) -> Result<Vec<u8>, NetworkError> {
    let transport = NativeWebSocketTransport::new(endpoint)?;
    NetworkClient::new(transport)
        .call(Operation::GetBlockDagInfo, &[mode as u8])
        .await
}

#[tokio::test]
async fn actual_websocket_transport_handles_simulated_faults_fail_closed() {
    let server = FaultServer::bind().await.expect("bind fault server");
    let endpoint = server.endpoint().expect("fault endpoint");
    let task = tokio::spawn(server.serve());

    for mode in [FaultMode::Valid, FaultMode::Delayed, FaultMode::Duplicate] {
        assert_eq!(call(&endpoint, mode).await.expect("valid fault response"), b"fault-ok");
    }

    assert!(matches!(
        call(&endpoint, FaultMode::Malformed).await,
        Err(NetworkError::TruncatedPayload)
    ));
    assert!(matches!(
        call(&endpoint, FaultMode::MismatchedId).await,
        Err(NetworkError::MismatchedRequestId { .. })
    ));
    assert!(matches!(
        call(&endpoint, FaultMode::MismatchedOperation).await,
        Err(NetworkError::MismatchedOperation { .. })
    ));
    assert!(matches!(
        call(&endpoint, FaultMode::RemoteError).await,
        Err(NetworkError::RemoteError(message)) if message.contains("simulated remote error")
    ));
    assert!(matches!(
        call(&endpoint, FaultMode::CloseBeforeResponse).await,
        Err(NetworkError::ConnectionFailed(_))
    ));
    assert!(matches!(
        call(&endpoint, FaultMode::TextBeforeBinary).await,
        Err(NetworkError::UnexpectedResponse(message)) if message.contains("non-binary")
    ));

    for index in 0..32 {
        let mode = match index % 4 {
            0 => FaultMode::Malformed,
            1 => FaultMode::MismatchedId,
            2 => FaultMode::MismatchedOperation,
            _ => FaultMode::CloseBeforeResponse,
        };
        assert!(call(&endpoint, mode).await.is_err());
        assert_eq!(
            call(&endpoint, FaultMode::Valid)
                .await
                .expect("transport recovers after injected fault"),
            b"fault-ok"
        );
    }

    task.abort();
}
