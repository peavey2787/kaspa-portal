use super::{is_single_path, spend_path, SpendPath};
use crate::contract::script::push_data;

fn spend(selector: u8, redeem: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    push_data(&mut script, &[7; 65]);
    script.push(selector);
    push_data(&mut script, redeem);
    script
}

#[test]
fn single_path_covenants_open_with_a_key_checksigverify() {
    let mut owner_only = vec![32];
    owner_only.extend([1; 32]);
    owner_only.extend([0xad, 0x51]);
    assert!(is_single_path(&owner_only));
    let mut salted = vec![8];
    salted.extend([2; 8]);
    salted.push(0x75);
    salted.extend(&owner_only);
    assert!(is_single_path(&salted));
    assert!(!is_single_path(&[0x63, 0x51, 0x67, 0x51, 0x68]));
    assert!(!is_single_path(&[]));
    assert_eq!(spend_path(&[], &owner_only), Some(SpendPath::Owner));
}

#[test]
fn two_branch_spends_report_the_selector_before_the_redeem_push() {
    let redeem = [0x63, 0x51, 0x67, 0x51, 0x68];
    assert_eq!(
        spend_path(&spend(0x51, &redeem), &redeem),
        Some(SpendPath::Owner)
    );
    assert_eq!(
        spend_path(&spend(0x00, &redeem), &redeem),
        Some(SpendPath::Other)
    );
    assert_eq!(spend_path(&spend(0x52, &redeem), &redeem), None);
    assert_eq!(spend_path(&spend(0x51, &redeem), &[0x51]), None);
    let truncated = spend(0x51, &redeem);
    assert_eq!(spend_path(&truncated[..truncated.len() - 1], &redeem), None);
    assert_eq!(spend_path(&[0x51], &redeem), None);
}
