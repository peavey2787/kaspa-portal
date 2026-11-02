use super::reserved_records;
use crate::transaction::model::{Transaction, MAX_SIGS_PER_INPUT};

#[test]
fn records_are_reserved_for_every_possible_signature_up_front() {
    let mut tx = Transaction::try_new().expect("transaction storage");
    tx.ensure_input_slots(3).expect("inputs");
    tx.num_inputs = 3;
    let records = reserved_records::<u8>(&tx).expect("reservation");
    assert!(records.is_empty());
    assert!(records.capacity() >= 3 * MAX_SIGS_PER_INPUT);
}
