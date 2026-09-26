use crate::network::{
    codec::{primitives::WireWriter, requests::subscription},
    wrpc::notification::{
        self, Notification, UTXOS_CHANGED_NOTIFICATION_OPERATION,
        VIRTUAL_DAA_SCORE_CHANGED_NOTIFICATION_OPERATION,
    },
};

/// Entries blob (`u32 count` + length-prefixed entries) from the stable
/// GetUtxosByAddresses fixture: one entry, txid 22.., index 3, amount 4.
fn one_entry_blob() -> Vec<u8> {
    let response = hex::decode(concat!(
        "0177000000010071000000010000006900000001002500000001",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "030000003a000000020400000000000000000001000000510500000000000000",
        "00013333333333333333333333333333333333333333333333333333333333333333"
    ))
    .unwrap();
    response[11..].to_vec()
}

fn frame(operation: u8, variant: u16, body: &[u8]) -> Vec<u8> {
    let mut notification = WireWriter::new();
    notification.write_u16(1);
    notification.write_u16(variant);
    notification.write_bytes(body).unwrap();
    let mut payload = WireWriter::new();
    payload.write_bytes(&notification.into_vec()).unwrap();
    let mut frame = WireWriter::new();
    frame.write_u8(0); // no request id
    frame.write_u8(0xff); // server notification
    frame.write_u8(1); // operation present
    frame.write_u8(operation);
    frame.write_raw(&payload.into_vec());
    frame.into_vec()
}

#[test]
fn utxos_changed_notifications_decode_added_and_removed_entries() {
    let mut body = WireWriter::new();
    body.write_u16(1);
    body.write_bytes(&one_entry_blob()).unwrap();
    body.write_bytes(&0u32.to_le_bytes()).unwrap();
    let decoded = notification::decode(&frame(
        UTXOS_CHANGED_NOTIFICATION_OPERATION,
        4,
        &body.into_vec(),
    ))
    .unwrap()
    .unwrap();
    let Notification::UtxosChanged(changed) = decoded else {
        panic!("expected UtxosChanged");
    };
    assert_eq!(changed.added.len(), 1);
    assert_eq!(changed.added[0].tx_id, "22".repeat(32));
    assert_eq!(changed.added[0].amount, 4);
    assert!(changed.removed.is_empty());
}

#[test]
fn virtual_daa_score_notifications_decode_the_score() {
    let mut body = WireWriter::new();
    body.write_u16(1);
    body.write_u64(987_654);
    let raw = frame(
        VIRTUAL_DAA_SCORE_CHANGED_NOTIFICATION_OPERATION,
        6,
        &body.into_vec(),
    );
    assert!(matches!(
        notification::decode(&raw).unwrap(),
        Some(Notification::VirtualDaaScoreChanged(987_654))
    ));
}

#[test]
fn unsupported_or_mislabelled_notifications_fail_closed() {
    assert!(notification::decode(&[0, 0xff, 1, 61]).unwrap().is_none());
    let mut body = WireWriter::new();
    body.write_u16(1);
    body.write_u64(1);
    let wrong_variant = frame(
        VIRTUAL_DAA_SCORE_CHANGED_NOTIFICATION_OPERATION,
        4,
        &body.into_vec(),
    );
    assert!(notification::decode(&wrong_variant).is_err());
    // A response (with a request id) is never a notification.
    assert!(notification::decode(&[1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3]).is_err());
}

#[test]
fn subscription_bodies_carry_scope_and_addresses() {
    let daa = subscription::virtual_daa_score_changed_payload().unwrap();
    assert_eq!(&daa[..6], &[1, 0, 6, 0, 0, 0]);
    let address =
        "kaspatest:qpq863qwr7nqmfyz8qs3acpd0w6u6cert23pw55fqc6y9ar9vl8ajn9f0y8kl".to_string();
    let utxos = subscription::utxos_changed_payload(&[address.clone(), address]).unwrap();
    assert_eq!(&utxos[..6], &[1, 0, 4, 0, 0, 0]);
    assert!(utxos.len() > daa.len());
}
