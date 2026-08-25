use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultMode {
    Valid = 0,
    Delayed = 1,
    Duplicate = 2,
    Malformed = 3,
    MismatchedId = 4,
    MismatchedOperation = 5,
    RemoteError = 6,
    CloseBeforeResponse = 7,
    TextBeforeBinary = 8,
}

impl FaultMode {
    fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Delayed,
            2 => Self::Duplicate,
            3 => Self::Malformed,
            4 => Self::MismatchedId,
            5 => Self::MismatchedOperation,
            6 => Self::RemoteError,
            7 => Self::CloseBeforeResponse,
            8 => Self::TextBeforeBinary,
            _ => Self::Valid,
        }
    }
}

pub struct FaultServer {
    listener: TcpListener,
}

impl FaultServer {
    pub async fn bind() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { listener })
    }

    pub fn endpoint(&self) -> Result<String, String> {
        self.listener
            .local_addr()
            .map(|address| format!("ws://{address}"))
            .map_err(|error| error.to_string())
    }

    pub async fn serve(self) -> Result<(), String> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(|error| error.to_string())?;
            tokio::spawn(async move {
                let _ = handle_connection(stream).await;
            });
        }
    }
}

async fn handle_connection(stream: TcpStream) -> Result<(), String> {
    let mut websocket = accept_async(stream).await.map_err(|error| error.to_string())?;
    let request = loop {
        match websocket.next().await {
            Some(Ok(Message::Binary(bytes))) => break bytes.to_vec(),
            Some(Ok(Message::Close(_))) | None => return Ok(()),
            Some(Ok(_)) => continue,
            Some(Err(error)) => return Err(error.to_string()),
        }
    };
    let (request_id, operation, mode) = parse_request(&request)?;
    let response = success_response(request_id, operation, b"fault-ok");
    match mode {
        FaultMode::Valid => send_binary(&mut websocket, response).await?,
        FaultMode::Delayed => {
            tokio::time::sleep(Duration::from_millis(250)).await;
            send_binary(&mut websocket, response).await?;
        }
        FaultMode::Duplicate => {
            send_binary(&mut websocket, response.clone()).await?;
            let _ = send_binary(&mut websocket, response).await;
        }
        FaultMode::Malformed => send_binary(&mut websocket, vec![1, 2]).await?,
        FaultMode::MismatchedId => {
            send_binary(
                &mut websocket,
                success_response(request_id.wrapping_add(1), operation, b"bad-id"),
            )
            .await?;
        }
        FaultMode::MismatchedOperation => {
            let wrong = if operation == 131 { 147 } else { 131 };
            send_binary(&mut websocket, success_response(request_id, wrong, b"bad-op")).await?;
        }
        FaultMode::RemoteError => {
            send_binary(
                &mut websocket,
                error_response(request_id, operation, b"simulated remote error"),
            )
            .await?;
        }
        FaultMode::CloseBeforeResponse => {
            websocket.close(None).await.map_err(|error| error.to_string())?;
        }
        FaultMode::TextBeforeBinary => {
            websocket
                .send(Message::Text("unexpected text frame".into()))
                .await
                .map_err(|error| error.to_string())?;
            let _ = send_binary(&mut websocket, response).await;
        }
    }
    Ok(())
}

async fn send_binary<S>(websocket: &mut S, bytes: Vec<u8>) -> Result<(), String>
where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    websocket
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|error| error.to_string())
}

fn parse_request(bytes: &[u8]) -> Result<(u64, u8, FaultMode), String> {
    if bytes.len() < 14 || bytes[0] != 1 {
        return Err("malformed fault-server request".into());
    }
    let request_id = u64::from_le_bytes(bytes[1..9].try_into().map_err(|_| "bad request id")?);
    let operation = bytes[9];
    let payload_len = u32::from_le_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| "bad payload length")?,
    );
    let payload_len = usize::try_from(payload_len).map_err(|_| "payload length exceeds usize")?;
    let payload_end = 14usize
        .checked_add(payload_len)
        .ok_or("payload length overflow")?;
    if payload_end > bytes.len() {
        return Err("truncated fault-server payload".into());
    }
    let mode = FaultMode::from_byte(bytes.get(14).copied().unwrap_or(0));
    Ok((request_id, operation, mode))
}

fn success_response(request_id: u64, operation: u8, payload: &[u8]) -> Vec<u8> {
    response(request_id, operation, 0, payload)
}

fn error_response(request_id: u64, operation: u8, payload: &[u8]) -> Vec<u8> {
    response(request_id, operation, 1, payload)
}

fn response(request_id: u64, operation: u8, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12 + payload.len());
    bytes.push(1);
    bytes.extend_from_slice(&request_id.to_le_bytes());
    bytes.push(kind);
    bytes.push(1);
    bytes.push(operation);
    bytes.extend_from_slice(payload);
    bytes
}
