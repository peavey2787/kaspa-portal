use crate::network::error::NetworkError;

pub fn decode(data: &[u8]) -> Result<String, NetworkError> {
    if data.is_empty() {
        return Err(NetworkError::UnexpectedResponse(
            "empty transaction response".into(),
        ));
    }
    let text = String::from_utf8_lossy(data);
    if contains_error(&text) {
        return Err(NetworkError::RemoteError(text.chars().take(200).collect()));
    }
    if data[0] == 0 {
        return Err(NetworkError::RemoteError(decode_tagged_error(data)));
    }

    let inner = unwrap_success(data);
    let inner_text = String::from_utf8_lossy(inner);
    if contains_error(&inner_text) {
        return Err(NetworkError::RemoteError(
            inner_text.chars().take(200).collect(),
        ));
    }
    if inner.len() >= 34 {
        Ok(hex::encode(&inner[2..34]))
    } else if inner.len() >= 2 {
        Ok(hex::encode(inner))
    } else {
        Ok("broadcast_ok".into())
    }
}

fn contains_error(text: &str) -> bool {
    ["Reject", "reject", "error", "Error"]
        .iter()
        .any(|needle| text.contains(needle))
}

pub(crate) fn decode_tagged_error(data: &[u8]) -> String {
    if data.len() > 5 {
        let encoded_length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let length = match usize::try_from(encoded_length) {
            Ok(length) => length,
            Err(_) => usize::MAX,
        };
        let end = 5usize.saturating_add(length).min(data.len());
        return String::from_utf8_lossy(&data[5..end]).into_owned();
    }
    "transaction rejected by node".into()
}

fn unwrap_success(data: &[u8]) -> &[u8] {
    if data.len() <= 5 {
        return data;
    }
    let start = if data[0] == 1 { 1 } else { 0 };
    if start + 4 > data.len() {
        return data;
    }
    let length_bytes = [
        data[start],
        data[start + 1],
        data[start + 2],
        data[start + 3],
    ];
    let encoded_length = u32::from_le_bytes(length_bytes);
    let length = match usize::try_from(encoded_length) {
        Ok(length) => length,
        Err(_) => usize::MAX,
    };
    let end = start
        .saturating_add(4)
        .saturating_add(length)
        .min(data.len());
    &data[start + 4..end]
}
