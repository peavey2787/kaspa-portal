#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 250,
            max_delay_ms: 4_000,
        }
    }
}
impl RetryPolicy {
    pub fn delay_ms(self, attempt: u8) -> u64 {
        let shift = u32::from(attempt.saturating_sub(1).min(8));
        self.base_delay_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_delay_ms)
    }
}
