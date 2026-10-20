//! The success envelope every Kaspa wRPC response payload shares.

use crate::network::{codec::primitives::WireReader, error::NetworkError};

/// A success payload opens with this marker before the length-prefixed
/// `Serializable` response.
const RESPONSE_PRESENT: u8 = 1;

/// The body of a versioned response, positioned after its `u16` version.
/// The marker, the length prefix and the end of the payload are all
/// required, so a short or padded reply is an error, never an empty answer.
pub(super) fn response_body<'a>(
    data: &'a [u8],
    max_bytes: usize,
    response: &str,
) -> Result<WireReader<'a>, NetworkError> {
    let mut reader = WireReader::new(data);
    if reader.read_u8()? != RESPONSE_PRESENT {
        return Err(NetworkError::InvalidEncoding(format!(
            "{response} is missing its payload marker"
        )));
    }
    let body = reader.read_bytes(max_bytes)?;
    require_consumed(&reader, response)?;
    let mut body = WireReader::new(body);
    body.read_u16()?;
    Ok(body)
}

pub(super) fn require_consumed(
    reader: &WireReader<'_>,
    response: &str,
) -> Result<(), NetworkError> {
    if reader.remaining().is_empty() {
        Ok(())
    } else {
        Err(NetworkError::InvalidEncoding(format!(
            "trailing bytes after {response}"
        )))
    }
}
