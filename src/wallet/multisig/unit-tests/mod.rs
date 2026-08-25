use super::{build_redeem_script, resolve_address_path, MultisigDescriptor};

const FIRST: &str = "kpub1:038f332e03405ab68380000000f0453f0894cc8c84ebf6e6208e0c7916e9ddbd14919f9bbb92b0690b4e353392020327c7136972883eab5a7722ec3d4302f888804ecce61658ae962a2c56bb7571";
const SECOND: &str = "kpub1:038f332e03a7457270800000002908be01d75735944f29befbdbcd173ab00df2d44c6d5ab51a839413fda90cbf035b986b584de244f5d6a1939192f676a9f2992a63b0f43cdc452dcb40d9dd7081";

#[test]
fn static_descriptor_is_sorted_before_script_encoding() {
    let descriptor = MultisigDescriptor::parse(&format!(
        "multi(1,{}, {})",
        "02".repeat(32),
        "01".repeat(32)
    ))
    .expect("descriptor");
    let keys = descriptor.public_keys_at(0, 0, 0).expect("keys");
    assert!(keys[0] < keys[1]);
    let script = build_redeem_script(descriptor.threshold(), &keys).expect("script");
    assert_eq!(script[0], 0x51);
    assert_eq!(script.last(), Some(&0xae));
}

#[test]
fn descriptor_parser_accepts_static_and_hd45_only() {
    let hd = MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{SECOND})"))
        .expect("45' descriptor");
    assert!(hd.is_hd());
    assert!(hd.is_hd45());
    assert_eq!(hd.threshold(), 1);
    assert_eq!(hd.participant_count(), 2);
    assert_eq!(hd.public_keys_at(7, 0, 0).expect("keys").len(), 2);

    for invalid in [
        "multi_hd(1,a,b)",
        "multi_hd45(1,only-one)",
        "multi_hd45(0,a,b)",
        "multi_hd45(3,a,b)",
        "multi_hd45(not-a-number,a,b)",
        "unknown(1,a,b)",
    ] {
        assert!(
            MultisigDescriptor::parse(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn static_address_path_resolution_returns_requested_index() {
    let descriptor =
        MultisigDescriptor::parse(&format!("multi(1,{},{})", "01".repeat(32), "02".repeat(32),))
            .expect("static descriptor");
    assert_eq!(
        resolve_address_path(&descriptor, "kaspa:any", 37).map(|path| path.index),
        Ok(37),
    );
}

#[test]
fn hd45_cross_implementation_vector_is_exact() {
    const KPUBS: [&str; 5] = [
        "kpub1:038f332e03405ab68380000000f0453f0894cc8c84ebf6e6208e0c7916e9ddbd14919f9bbb92b0690b4e353392020327c7136972883eab5a7722ec3d4302f888804ecce61658ae962a2c56bb7571",
        "kpub1:038f332e03a7457270800000002908be01d75735944f29befbdbcd173ab00df2d44c6d5ab51a839413fda90cbf035b986b584de244f5d6a1939192f676a9f2992a63b0f43cdc452dcb40d9dd7081",
        "kpub1:038f332e037a262d628000000037234957045cdffdb77c3fdcb25649de3326bd8eb6459276a96ba0b14b99cf05034cf53938d64f4a3d4554e18e9ec0d113b251be5b974386807e95a58530e837e1",
        "kpub1:038f332e03206bbc9880000000d67b1d630674ca46e41e4bc5f6fc953a832efc679d85f80f7c01e494d993684402c0b5ff5ef462947cef268431e0ea913e6b5f51c5d8a572b10ba25ebbbca11440",
        "kpub1:038f332e03d18681ae80000000524d81044c2fad73c8d8e07cf3ec0d21b1b0bfb9163b78b900f4b9ba60f7658a036c8c95588515593aa406c778888410de0a7df460483529d10ae241adf6e2a19f",
    ];
    const EXPECTED: &str = "kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998";

    let descriptor = MultisigDescriptor::parse(&format!(
        "multi_hd45(2,{},{},{},{},{})",
        KPUBS[0], KPUBS[1], KPUBS[2], KPUBS[3], KPUBS[4],
    ))
    .expect("descriptor");
    let keys = descriptor.public_keys_at(0, 1, 0).expect("45' children");
    let redeem = build_redeem_script(2, &keys).expect("45' redeem");
    let address =
        crate::contract::script::p2sh::script_to_address(&redeem, "kaspa").expect("45' P2SH");
    assert_eq!(address, EXPECTED);
}

#[test]
fn hd45_parser_rejects_duplicates_bad_input_and_invalid_chain() {
    assert!(
        MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{FIRST})"))
            .unwrap_err()
            .contains("Duplicate cosigner")
    );
    assert!(MultisigDescriptor::parse("multi_hd45(1,short,also-short)").is_err());
    let invalid = "x".repeat(111);
    assert!(
        MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{invalid})"))
            .unwrap_err()
            .contains("Invalid 45' cosigner account key")
    );

    let descriptor =
        MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{SECOND})")).expect("descriptor");
    assert!(descriptor
        .public_keys_at(0, 0, 2)
        .unwrap_err()
        .contains("chain"));
}

#[test]
fn hd45_address_path_resolution_covers_cosigner_and_change_branches() {
    let descriptor = MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{SECOND})"))
        .expect("45' descriptor");
    let keys = descriptor.public_keys_at(2, 1, 1).expect("change keys");
    let redeem = build_redeem_script(1, &keys).expect("change redeem");
    let address =
        crate::contract::script::p2sh::script_to_address(&redeem, "kaspa").expect("change address");
    let path = resolve_address_path(&descriptor, &address, 99).expect("resolved path");
    assert_eq!((path.cosigner, path.chain, path.index), (1, 1, 2));
}

#[test]
fn redeem_script_validation_covers_threshold_count_and_conversion_boundaries() {
    let one = [[0x11u8; 32]];
    assert!(build_redeem_script(0, &one)
        .unwrap_err()
        .contains("Invalid 0-of-1"));
    assert!(build_redeem_script(2, &one)
        .unwrap_err()
        .contains("Invalid 2-of-1"));

    let seventeen = vec![[0x22u8; 32]; 17];
    assert!(build_redeem_script(1, &seventeen)
        .unwrap_err()
        .contains("Invalid 1-of-17"));

    let too_many = vec![[0x33u8; 32]; 256];
    assert!(build_redeem_script(1, &too_many)
        .unwrap_err()
        .contains("Too many multisig"));
}
