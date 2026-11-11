//! The key that spends a stealth output: the even-Y account key plus the
//! output's tweak.

use k256::elliptic_curve::{ops::Add, sec1::ToSec1Point, ScalarValue};
use k256::{ProjectivePoint, Scalar, Secp256k1};

use super::{context::SigningKeyMaterial, PsktError};

/// Derive the stealth spend key, keeping it only if its x-only public key is
/// `target_xonly`. An account key or tweak that is not a valid scalar is a
/// derivation failure.
pub(super) fn stealth_spend_key(
    account_private_key: &[u8; 32],
    tweak: &[u8; 32],
    target_xonly: &[u8; 32],
) -> Result<Option<SigningKeyMaterial>, PsktError> {
    let account = ScalarValue::<Secp256k1>::from_slice(account_private_key)
        .map_err(|_| PsktError::DerivationFailed)?;
    let tweak =
        ScalarValue::<Secp256k1>::from_slice(tweak).map_err(|_| PsktError::DerivationFailed)?;
    let combined = even_y(Scalar::from(account)).add(&Scalar::from(tweak));
    let point = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_sec1_point(true);
    if &point.as_bytes()[1..33] != target_xonly {
        return Ok(None);
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&combined.to_bytes());
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(point.as_bytes());
    Ok(Some(SigningKeyMaterial {
        private_key,
        compressed_public_key,
    }))
}

/// The scalar whose public key has an even Y coordinate, as BIP-340 expects.
fn even_y(scalar: Scalar) -> Scalar {
    let encoded = (ProjectivePoint::GENERATOR * scalar)
        .to_affine()
        .to_sec1_point(true);
    if encoded.as_bytes()[0] == 0x03 {
        -scalar
    } else {
        scalar
    }
}
