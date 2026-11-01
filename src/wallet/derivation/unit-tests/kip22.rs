use super::*;
use crate::primitives::address::{decode_address, p2sh_hash, p2sh_script};
use crate::wallet::derivation::bip32::derive_path as derive_full_path;

const SEED: [u8; 64] = [7; 64];
const HARD: u32 = HARDENED_BIT;

fn xonly(key: &ExtendedPrivKey) -> [u8; 32] {
    key.public_key_x_only().unwrap()
}

#[test]
fn redeem_script_is_the_key_then_checksig() {
    let key = [0xab; 32];
    let script = redeem_script(&key);
    assert_eq!(script[0], 0x20);
    assert_eq!(&script[1..33], &key);
    assert_eq!(script[33], 0xac);
}

#[test]
fn address_commits_to_the_script_hash_and_hides_the_key() {
    let key = [0xab; 32];
    let (version, payload) = decode_address(&address(&key, "kaspa")).unwrap();
    assert_eq!(version, 0x08);
    assert_eq!(payload, redeem_script_hash(&key));
    assert_ne!(payload, key);
    assert_eq!(p2sh_hash(&p2sh_script(&payload)), Some(payload));
}

#[test]
fn testnet_uses_the_same_key_and_payload_under_its_own_prefix() {
    let key = [0xab; 32];
    let main = address(&key, "kaspa");
    let test = address(&key, "kaspatest");
    assert!(test.starts_with("kaspatest:"));
    assert_eq!(
        decode_address(&main).unwrap().1,
        decode_address(&test).unwrap().1
    );
}

#[test]
fn keys_sit_on_the_specified_path() {
    for (account, chain, chain_index, index) in [
        (0, Chain::Receive, 0, 0),
        (0, Chain::Change, 1, 5),
        (3, Chain::Receive, 0, 9),
    ] {
        let derived =
            derive_address_key(&derive_account_key(&SEED, account).unwrap(), chain, index).unwrap();
        let path = [
            22 + HARD,
            111_111 + HARD,
            account + HARD,
            chain_index,
            index,
        ];
        assert_eq!(
            xonly(&derived),
            xonly(&derive_full_path(&SEED, &path).unwrap())
        );
    }
}

#[test]
fn kip22_keys_differ_from_bip44_keys() {
    let kip22 =
        derive_address_key(&derive_account_key(&SEED, 0).unwrap(), Chain::Receive, 0).unwrap();
    let bip44 = derive_full_path(&SEED, &[44 + HARD, 111_111 + HARD, HARD, 0, 0]).unwrap();
    assert_ne!(xonly(&kip22), xonly(&bip44));
}

#[test]
fn out_of_range_levels_are_rejected() {
    assert!(derive_account_key(&SEED, HARD).is_err());
    let account = derive_account_key(&SEED, 0).unwrap();
    assert!(derive_address_key(&account, Chain::Receive, HARD).is_err());
}

#[test]
fn own_scripts_are_found_on_their_chain_and_others_are_not() {
    let account = derive_account_key(&SEED, 0).unwrap();
    let key = xonly(&derive_address_key(&account, Chain::Change, 4).unwrap());
    let script = p2sh_script(&redeem_script_hash(&key));
    assert_eq!(
        find_owned_script(&account, &script, &mut || {}),
        Some((Chain::Change, 4))
    );
    let foreign = p2sh_script(&redeem_script_hash(&[0xab; 32]));
    assert_eq!(find_owned_script(&account, &foreign, &mut || {}), None);
}

#[test]
fn only_the_key_then_checksig_is_a_redeem_script() {
    assert!(is_redeem_script(&redeem_script(&[0xab; 32])));
    assert!(!is_redeem_script(&[0x20; REDEEM_SCRIPT_LEN]));
    assert!(!is_redeem_script(&[]));
}
