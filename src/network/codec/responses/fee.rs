use super::envelope::response_body;
use crate::network::{
    codec::primitives::WireReader, error::NetworkError, model::fee_estimate::FeeEstimate,
};

/// 1 MiB.
const MAX_BLOB_BYTES: usize = 1_048_576;
const MAX_BUCKETS: usize = 10_000;

fn decode_estimate(estimate: &[u8]) -> Result<FeeEstimate, NetworkError> {
    let mut reader = WireReader::new(estimate);
    reader.read_u16()?;
    let priority_sompi_per_gram = reader.read_f64()?;
    let priority_seconds = reader.read_f64()?;
    let (normal_sompi_per_gram, normal_seconds) = read_first_bucket(&mut reader, 1.0, 30.0)?;
    let (low_sompi_per_gram, low_seconds) = read_first_bucket(&mut reader, 1.0, 1800.0)?;
    let suggested_fee = (normal_sompi_per_gram * 2300.0).max(10_000.0) as u64;
    Ok(FeeEstimate {
        priority_sompi_per_gram,
        normal_sompi_per_gram,
        low_sompi_per_gram,
        priority_seconds,
        normal_seconds,
        low_seconds,
        suggested_fee,
    })
}

/// Callers choose their own fallback rate when the node's answer is unusable.
pub fn decode(data: &[u8]) -> Result<FeeEstimate, NetworkError> {
    let mut response = response_body(data, MAX_BLOB_BYTES, "GetFeeEstimateResponse")?;
    decode_estimate(response.read_bytes(MAX_BLOB_BYTES)?)
}

fn read_first_bucket(
    reader: &mut WireReader<'_>,
    default_rate: f64,
    default_seconds: f64,
) -> Result<(f64, f64), NetworkError> {
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_BUCKETS {
        return Err(NetworkError::InvalidLength);
    }
    let mut selected = (default_rate, default_seconds);
    for index in 0..count {
        let bucket = (reader.read_f64()?, reader.read_f64()?);
        if index == 0 {
            selected = bucket;
        }
    }
    Ok(selected)
}
