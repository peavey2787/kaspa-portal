use kaspa_portal::{transaction::model::SigHashType, KaspaPortal, Result};

fn main() -> Result<()> {
    let Some(wire_hex) = std::env::args().nth(1) else {
        eprintln!("usage: cargo run --example offline_signing -- <compact-kspt-hex> <32-byte-private-key-hex>");
        return Ok(());
    };
    let Some(secret_hex) = std::env::args().nth(2) else {
        eprintln!("missing private key");
        return Ok(());
    };
    let wire = hex::decode(wire_hex)
        .map_err(|error| kaspa_portal::Error::Transaction(format!("invalid wire hex: {error}")))?;
    let secret: [u8; 32] = hex::decode(secret_hex)
        .map_err(|error| kaspa_portal::Error::Transaction(format!("invalid key hex: {error}")))?
        .try_into()
        .map_err(|_| kaspa_portal::Error::Transaction("private key must be 32 bytes".into()))?;

    let portal = KaspaPortal::builder().build()?;
    let signed = portal
        .transaction()
        .sign_compact_kspt(&wire, &secret, SigHashType::All)?;
    println!("signed {} input(s)", signed.signatures.len());
    Ok(())
}
