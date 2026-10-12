use alloc::{string::ToString, vec::Vec};

use super::{krc20_operation, Krc20Op, Krc20Operation};
use crate::contract::script::push_data;

fn reveal(json: &[u8], tag: &[u8], close: bool) -> Vec<u8> {
    let mut script = Vec::new();
    push_data(&mut script, &[0x11; 32]);
    script.extend_from_slice(&[0xac, 0x00, 0x63]);
    push_data(&mut script, tag);
    script.push(0x00);
    push_data(&mut script, json);
    if close {
        script.push(0x68);
    }
    script
}

#[test]
fn transfer_mint_and_deploy_envelopes_decode() {
    let transfer =
        br#"{"p":"krc-20","op":"transfer","tick":"nacho","amt":"100000000","to":"kaspa:qz"}"#;
    assert_eq!(
        krc20_operation(&reveal(transfer, b"kasplex", true)),
        Some(Krc20Operation {
            op: Krc20Op::Transfer,
            ticker: "NACHO".to_string(),
            amount: Some("100000000".to_string()),
            recipient: Some("kaspa:qz".to_string()),
        })
    );
    let mint = br#"{"p":"KRC-20","op":"MINT","tick":"KASPY"}"#;
    let parsed = krc20_operation(&reveal(mint, b"kasplex", true)).expect("mint");
    assert_eq!((parsed.op, parsed.amount), (Krc20Op::Mint, None));
    let deploy = br#"{"p":"krc-20","op":"deploy","tick":"TEST","max":"21000000","lim":"1000"}"#;
    assert_eq!(
        krc20_operation(&reveal(deploy, b"kasplex", true)).map(|op| op.op),
        Some(Krc20Op::Deploy)
    );
    let other = br#"{"p":"krc-20","op":"list","tick":"TEST"}"#;
    assert_eq!(
        krc20_operation(&reveal(other, b"kasplex", true)).map(|op| op.op.label()),
        Some("?")
    );
    assert_eq!(Krc20Op::Transfer.label(), "TRANSFER");
    assert_eq!(Krc20Op::Mint.label(), "MINT");
    assert_eq!(Krc20Op::Deploy.label(), "DEPLOY");
}

#[test]
fn anything_but_a_closed_kasplex_krc20_envelope_is_ignored() {
    let transfer = br#"{"p":"krc-20","op":"transfer","tick":"NACHO"}"#;
    assert!(krc20_operation(&reveal(transfer, b"kasplex", false)).is_none());
    assert!(krc20_operation(&reveal(transfer, b"ordinal", true)).is_none());
    let other_protocol = br#"{"p":"brc-20","op":"transfer","tick":"NACHO"}"#;
    assert!(krc20_operation(&reveal(other_protocol, b"kasplex", true)).is_none());
    let no_ticker = br#"{"p":"krc-20","op":"transfer","tick":""}"#;
    assert!(krc20_operation(&reveal(no_ticker, b"kasplex", true)).is_none());
    assert!(krc20_operation(&reveal(b"not json", b"kasplex", true)).is_none());
    // JSON that merely appears in a script outside an envelope.
    let mut loose = Vec::new();
    push_data(&mut loose, transfer);
    assert!(krc20_operation(&loose).is_none());
    assert!(krc20_operation(&[]).is_none());
}
