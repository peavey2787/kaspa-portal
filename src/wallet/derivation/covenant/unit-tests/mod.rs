use super::*;
use crate::wallet::derivation::bip32::{derive_account_key, derive_address_key};

#[test]
fn covenant_keys_are_instance_unique_and_spend_path_isolated() {
    let seed = [7u8; 64];
    let a = covenant_public_key(&seed, &[1u8; 32]).expect("a");
    let b = covenant_public_key(&seed, &[2u8; 32]).expect("b");
    assert_ne!(a, b);
    let account = derive_account_key(&seed).expect("account");
    let spend = derive_address_key(&account, 0)
        .expect("spend")
        .public_key_x_only()
        .expect("pub");
    assert_ne!(a, spend);
}

#[test]
fn covenant_signing_preserves_exact_commitment() {
    let seed = [11u8; 64];
    let key_id = [9u8; 32];
    let commitment = [0xa5u8; 32];
    let aux = [3u8; 32];
    let signature =
        provisional_covenant_signature(&seed, &key_id, &commitment, &aux).expect("sign");
    let pubkey = covenant_public_key(&seed, &key_id).expect("pubkey");
    assert!(schnorr::schnorr_verify(&pubkey, &commitment, &signature).is_ok());
    let mut changed = commitment;
    changed[0] ^= 1;
    assert!(schnorr::schnorr_verify(&pubkey, &changed, &signature).is_err());
}

#[test]
fn covenant_final_signature_includes_host_nonce_without_rehashing_commitment() {
    let seed = [21u8; 64];
    let key_id = [22u8; 32];
    let commitment = [0x5au8; 32];
    let provisional = provisional_covenant_signature(&seed, &key_id, &commitment, &[23u8; 32])
        .expect("provisional");
    let nonce_point = anti_klepto::provisional_nonce_point(&provisional);
    let session_id = [24u8; crate::transaction::signing::anti_klepto::SESSION_ID_LEN];
    let host_secret = [25u8; 32];
    let signature = finalize_covenant_signature(
        &seed,
        &key_id,
        &commitment,
        &provisional,
        &session_id,
        &host_secret,
    )
    .expect("final");
    let pubkey = covenant_public_key(&seed, &key_id).expect("pubkey");
    assert!(schnorr::schnorr_verify(&pubkey, &commitment, &signature).is_ok());
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&pubkey);
    assert!(anti_klepto::verify_nonce_relation(
        &nonce_point,
        &signature,
        &session_id,
        &host_secret,
        0,
        0,
        &compressed,
    )
    .is_ok());
}

#[test]
fn zero_instance_id_is_rejected() {
    assert_eq!(covenant_instance_indices(&[0u8; 32]), None);
}

#[test]
fn covenant_binding_token_is_script_specific_and_not_a_signing_key_signature() {
    let seed = [31u8; 64];
    let key_id = [32u8; 32];
    let script_a = [33u8; 32];
    let mut script_b = script_a;
    script_b[0] ^= 1;
    let token_a = covenant_binding_token(&seed, &key_id, &script_a).expect("binding a");
    let token_b = covenant_binding_token(&seed, &key_id, &script_b).expect("binding b");
    assert_ne!(token_a, token_b);
    assert!(covenant_binding_matches(&seed, &key_id, &script_a, &token_a).expect("match"));
    assert!(!covenant_binding_matches(&seed, &key_id, &script_b, &token_a).expect("mismatch"));
}

#[test]
fn private_swap_adaptor_secret_is_instance_specific_and_separate_from_claim_key() {
    let seed = [33u8; 64];
    let a = [34u8; 32];
    let b = [35u8; 32];
    let (mut secret_a, point_a) =
        private_swap_adaptor_secret_and_point(&seed, &a).expect("adaptor a");
    let (_, point_b) = private_swap_adaptor_secret_and_point(&seed, &b).expect("adaptor b");
    let generic_a = covenant_public_key(&seed, &a).expect("generic covenant");
    let claim_a = private_swap_public_key(&seed, &a).expect("swap claim");
    assert_ne!(point_a, point_b);
    assert_ne!(
        point_a, claim_a,
        "adaptor secret branch must not reuse the swap claim key"
    );
    assert_ne!(
        claim_a, generic_a,
        "Private Swap claim keys must be unreachable through generic COVENANT SIGN"
    );
    let generic_token = covenant_binding_token(&seed, &a, &[9u8; 32]).expect("generic token");
    let swap_token = private_swap_binding_token(&seed, &a, &[9u8; 32]).expect("swap token");
    assert_ne!(
        generic_token, swap_token,
        "binding domains must remain disjoint"
    );
    crate::primitives::bytes::zeroize_bytes(&mut secret_a);
}

#[test]
fn private_swap_covenant_adaptor_surface_roundtrips_and_binding_matches() {
    let seed = [0x41u8; 64];
    let instance = [0x42u8; 32];
    let script_hash = [0x43u8; 32];
    let token = private_swap_binding_token(&seed, &instance, &script_hash).expect("binding token");
    assert!(
        private_swap_binding_matches(&seed, &instance, &script_hash, &token)
            .expect("binding match")
    );
    let mut wrong_token = token;
    wrong_token[0] ^= 1;
    assert!(
        !private_swap_binding_matches(&seed, &instance, &script_hash, &wrong_token)
            .expect("binding mismatch")
    );

    let adaptor_point = private_swap_adaptor_point(&seed, &instance).expect("adaptor point");
    let message = [0x44u8; 32];
    let session_id = [0x45u8; 16];
    let aux_rand = [0x46u8; 32];
    let host_secret = [0x47u8; 32];
    let base_nonce = private_swap_adaptor_base_nonce_point(
        &seed,
        &instance,
        &message,
        &adaptor_point,
        &session_id,
        &aux_rand,
    )
    .expect("base nonce point");
    assert!(matches!(base_nonce[0], 0x02 | 0x03));

    let presignature = create_private_swap_adaptor_presignature(
        &seed,
        &instance,
        &message,
        &adaptor_point,
        &session_id,
        &aux_rand,
        &host_secret,
    )
    .expect("adaptor presignature");
    let completed = complete_private_swap_adaptor_presignature(&seed, &instance, &presignature)
        .expect("completed adaptor signature");
    let claim_pubkey = private_swap_public_key(&seed, &instance).expect("claim pubkey");
    let signature = SchnorrSignature { bytes: completed };
    assert!(schnorr::schnorr_verify(&claim_pubkey, &message, &signature).is_ok());
}

#[test]
fn covenant_derivation_and_binding_match_exact_independent_vectors() {
    let seed = [0x41u8; 64];
    let instance = [0x42u8; 32];
    let script_hash = [0x43u8; 32];

    assert_eq!(
        covenant_instance_indices(&instance),
        Some([
            0x24c0_78b9,
            0x708e_aa2e,
            0x085d_4bd0,
            0x2d2f_3079,
            0x6d4d_7427,
        ]),
    );
    assert_eq!(
        covenant_public_key(&seed, &instance).expect("covenant public key"),
        [
            0xc7, 0x8a, 0x0d, 0x83, 0xe2, 0x2a, 0xc3, 0x9b, 0xcd, 0xa2, 0x0f, 0xfa, 0x59, 0xa9,
            0x46, 0x20, 0x7e, 0x00, 0x1c, 0x2e, 0x29, 0x8f, 0x8a, 0x01, 0x7f, 0x0a, 0x85, 0xf3,
            0x75, 0x82, 0xb9, 0x9d,
        ],
    );
    assert_eq!(
        private_swap_public_key(&seed, &instance).expect("Private Swap public key"),
        [
            0x95, 0x2e, 0xf9, 0x5b, 0x51, 0x70, 0x30, 0x96, 0xeb, 0x69, 0xf6, 0x91, 0x6b, 0xb7,
            0x7c, 0xcd, 0x3d, 0xe5, 0x42, 0x54, 0x4c, 0x45, 0x31, 0xe9, 0x10, 0xe5, 0xd6, 0x4c,
            0xc9, 0xac, 0xbf, 0xce,
        ],
    );

    let covenant_token =
        covenant_binding_token(&seed, &instance, &script_hash).expect("covenant binding token");
    assert_eq!(
        covenant_token,
        [
            0x12, 0x43, 0x18, 0x35, 0x64, 0xf1, 0x18, 0x52, 0xc1, 0xaa, 0x3e, 0x98, 0xc4, 0x0f,
            0x8a, 0x65, 0x49, 0x3c, 0x50, 0xe5, 0x6b, 0xa6, 0xe0, 0x5f, 0x9b, 0x28, 0x8b, 0x5f,
            0x00, 0x31, 0xdc, 0xfa,
        ],
    );
    assert_eq!(
        private_swap_binding_token(&seed, &instance, &script_hash)
            .expect("Private Swap binding token"),
        [
            0x3b, 0xf3, 0xad, 0xdf, 0xa3, 0x98, 0xdd, 0x36, 0xd1, 0x05, 0x16, 0xfc, 0xae, 0x72,
            0xb9, 0xe8, 0x4b, 0xb1, 0x94, 0xe2, 0xc6, 0x15, 0x06, 0xbd, 0x40, 0x30, 0xd6, 0x81,
            0x23, 0xd5, 0x9d, 0xcd,
        ],
    );

    let (mut adaptor_secret, adaptor_point) =
        private_swap_adaptor_secret_and_point(&seed, &instance).expect("adaptor material");
    assert_eq!(
        adaptor_secret,
        [
            0xff, 0x5b, 0x67, 0xb3, 0x79, 0xd5, 0xb0, 0xb5, 0x2c, 0x99, 0x5f, 0x82, 0x4b, 0xe7,
            0x64, 0x19, 0x7c, 0xd3, 0x60, 0xc7, 0xa8, 0x95, 0x37, 0x6d, 0x5e, 0x06, 0xe8, 0x80,
            0x9b, 0x33, 0xca, 0xa1,
        ],
    );
    assert_eq!(
        adaptor_point,
        [
            0xf1, 0x6d, 0xd2, 0x19, 0xc5, 0x35, 0x5a, 0x19, 0x63, 0x24, 0x61, 0x5b, 0x2d, 0xf3,
            0xae, 0x00, 0x11, 0x98, 0x02, 0x4d, 0x19, 0xe8, 0x81, 0x16, 0x9b, 0x9c, 0x53, 0x1d,
            0x01, 0x5d, 0x92, 0x1f,
        ],
    );
    crate::primitives::bytes::zeroize_bytes(&mut adaptor_secret);

    // Two identical byte deltas cancel under XOR but not under the OR fold used
    // by constant_time_eq. This specifically locks in full-byte inequality.
    let mut cancellation_probe = covenant_token;
    cancellation_probe[0] ^= 1;
    cancellation_probe[1] ^= 1;
    assert!(
        !covenant_binding_matches(&seed, &instance, &script_hash, &cancellation_probe)
            .expect("two-byte mismatch")
    );
}

#[test]
fn covenant_error_conversions_preserve_error_domains() {
    assert!(matches!(
        CovenantKeyError::from(Bip32Error::InvalidKey),
        CovenantKeyError::Derivation(Bip32Error::InvalidKey)
    ));
    assert!(matches!(
        CovenantKeyError::from(SchnorrError::InvalidPrivateKey),
        CovenantKeyError::Signing(SchnorrError::InvalidPrivateKey)
    ));
    assert!(matches!(
        CovenantKeyError::from(anti_klepto::AntiKleptoError::InvalidHostContribution),
        CovenantKeyError::AntiKlepto(anti_klepto::AntiKleptoError::InvalidHostContribution)
    ));
}
