use super::retry_compact_vec;
use crate::transaction::{interchange::kspt::PsktError, model::Transaction};

#[test]
fn compact_vec_retry_covers_non_capacity_error_and_capacity_overflow() {
    let tx = Transaction::new();
    assert_eq!(
        retry_compact_vec(&tx, 1, PsktError::InvalidMagic),
        Err(PsktError::InvalidMagic),
    );
    assert_eq!(
        retry_compact_vec(&tx, usize::MAX, PsktError::OutputBufferTooSmall),
        Err(PsktError::OutputBufferTooSmall),
    );
}
