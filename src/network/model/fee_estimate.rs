use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FeeEstimate {
    pub priority_sompi_per_gram: f64,
    pub normal_sompi_per_gram: f64,
    pub low_sompi_per_gram: f64,
    pub priority_seconds: f64,
    pub normal_seconds: f64,
    pub low_seconds: f64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub suggested_fee: u64,
}
