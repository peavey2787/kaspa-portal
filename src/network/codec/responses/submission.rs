use crate::network::error::NetworkError;

pub fn decode(data: &[u8]) -> Result<String, NetworkError> {
    if data.is_empty() {
        return Err(NetworkError::UnexpectedResponse(
            "empty transaction response".into(),
        ));
    }
    if data[0] == 0 {
        return Err(NetworkError::RemoteError(decode_tagged_error(data)));
    }

    let inner = unwrap_success(data);
    if let Some(message) = extract_error_message(inner).or_else(|| extract_error_message(data)) {
        return Err(NetworkError::RemoteError(message));
    }
    if inner.len() >= 34 {
        Ok(hex::encode(&inner[2..34]))
    } else if inner.len() >= 2 {
        Ok(hex::encode(inner))
    } else {
        Ok("broadcast_ok".into())
    }
}

fn extract_error_message(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let start = [
        "Rejected transaction",
        "RPC error",
        "Error:",
        "error:",
        "error",
    ]
    .iter()
    .filter_map(|needle| text.find(needle))
    .min()?;
    let message = text[start..]
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .take(2_048)
        .collect::<String>();
    Some(
        message
            .trim_matches(|character: char| matches!(character, '\0' | ' ' | '\r' | '\n' | '\t'))
            .to_string(),
    )
}

pub(crate) fn decode_tagged_error(data: &[u8]) -> String {
    if data.len() > 5 {
        let encoded_length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let length = usize::try_from(encoded_length).unwrap_or(usize::MAX);
        let end = 5usize.saturating_add(length).min(data.len());
        return String::from_utf8_lossy(&data[5..end]).into_owned();
    }
    "transaction rejected by node".into()
}

/// The success body: an optional `1` tag, a `u32` length, then the bytes
/// (clipped to what arrived). Inputs too short to hold that are returned whole.
fn unwrap_success(data: &[u8]) -> &[u8] {
    if data.len() <= 5 {
        return data;
    }
    let body = &data[usize::from(data[0] == 1)..];
    let (length, rest) = body.split_at(4);
    let length = u32::from_le_bytes([length[0], length[1], length[2], length[3]]);
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    &rest[..length.min(rest.len())]
}
