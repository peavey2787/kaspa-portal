use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::network::{
    error::NetworkError,
    wrpc::{
        error_payload,
        operation::Operation,
        response::{self, ResponseKind},
    },
};

use super::websocket::NativeStream;

pub(super) fn reconnectable_transport_error(error: &NetworkError) -> bool {
    matches!(
        error,
        NetworkError::ConnectionFailed(_)
            | NetworkError::ConnectTimeout
            | NetworkError::ResponseTimeout
            | NetworkError::SendFailed
    )
}

pub(super) async fn receive_binary(stream: &mut NativeStream) -> Result<Vec<u8>, NetworkError> {
    while let Some(frame) = stream.next().await {
        match frame.map_err(|error| NetworkError::ConnectionFailed(error.to_string()))? {
            Message::Binary(bytes) => return Ok(bytes.to_vec()),
            Message::Ping(payload) => {
                stream
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| NetworkError::ConnectionFailed(error.to_string()))?;
            }
            Message::Close(frame) => {
                return Err(NetworkError::ConnectionFailed(format!(
                    "closed before Kaspa wRPC frame: {frame:?}"
                )))
            }
            Message::Text(_) => {
                return Err(NetworkError::UnexpectedResponse("non-binary frame".into()))
            }
            _ => {}
        }
    }
    Err(NetworkError::ConnectionFailed(
        "Kaspa wRPC connection ended".into(),
    ))
}

pub(super) fn validate_response(
    bytes: &[u8],
    expected_id: u64,
    expected_operation: Operation,
) -> Result<Vec<u8>, NetworkError> {
    let decoded = response::decode(bytes)?;
    match decoded.id {
        Some(actual) if actual == expected_id => {}
        Some(actual) => {
            return Err(NetworkError::MismatchedRequestId {
                expected: expected_id,
                actual,
            })
        }
        None => {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa notification received where RPC response was required".into(),
            ))
        }
    }
    if decoded.raw_operation.is_some() && decoded.operation != Some(expected_operation) {
        return Err(NetworkError::MismatchedOperation {
            expected: expected_operation.code(),
            actual: decoded.raw_operation.unwrap_or_default(),
        });
    }
    match decoded.kind {
        ResponseKind::Success => Ok(decoded.payload.to_vec()),
        ResponseKind::Error(code) => Err(NetworkError::RemoteError(format!(
            "kind={code}: {}",
            error_payload::decode(decoded.payload)
        ))),
        ResponseKind::Notification => Err(NetworkError::UnexpectedResponse(
            "Kaspa notification received where RPC response was required".into(),
        )),
    }
}
