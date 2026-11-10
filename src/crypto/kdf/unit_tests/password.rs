use alloc::vec;

use super::{
    derive_benchmark_key_32, derive_benchmark_key_32_with_workspace, derive_key_32,
    derive_key_32_with_params, derive_key_32_with_workspace, encode_metadata, parse_metadata,
    validate_benchmark_inputs, workspace_block_count, zeroize_workspace, PasswordKdfBlock,
    PasswordKdfError, PasswordKdfParams, PasswordKdfPurpose, ARGON2_VERSION_13, KDF_ID_ARGON2ID,
    PROFILE_VERSION_1, PROFILE_VERSION_2, V1_MEMORY_KIB, V1_PARALLELISM, V1_TIME_COST,
    V2_MEMORY_KIB,
};

const PASSWORD: &[u8] = b"CorrectHorse9";
const SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
// Independent vectors: argon2-cffi (reference C implementation), Argon2id v19,
// m=6144 KiB, t=3, p=1, salt = SHA-256 effective salt for each purpose domain.
const PORTABLE_EXPECTED: [u8; 32] = [
    0x5f, 0x5e, 0x20, 0x3b, 0x2f, 0x90, 0x85, 0x65, 0xe3, 0x59, 0xd3, 0xb3, 0x95, 0xe6, 0xe3, 0xc2,
    0x56, 0x3f, 0xf3, 0x42, 0x6b, 0x94, 0xbf, 0xfc, 0x26, 0x72, 0x4f, 0xed, 0x0b, 0xa3, 0x24, 0x4b,
];
// Same derivation with the v2 host profile (m=65536 KiB), argon2-cffi.
const PORTABLE_HOST_EXPECTED: [u8; 32] = [
    0x71, 0x16, 0x99, 0x0e, 0x2a, 0xd3, 0x81, 0x11, 0x46, 0x06, 0x67, 0x4f, 0x57, 0xd1, 0xc8, 0x4f,
    0xe0, 0x21, 0x97, 0x31, 0x7d, 0x5d, 0x89, 0x8c, 0x95, 0xde, 0x45, 0xd7, 0x22, 0x6f, 0xed, 0x8a,
];
const WALLET_EXPECTED: [u8; 32] = [
    0x50, 0xea, 0x7f, 0x1d, 0x84, 0x58, 0x42, 0xb2, 0xa1, 0x07, 0x16, 0x8e, 0xd8, 0x61, 0x58, 0xb7,
    0x50, 0x5c, 0xc7, 0x2b, 0x58, 0x9c, 0xc7, 0x91, 0xbd, 0xac, 0x8a, 0x78, 0xdf, 0x2c, 0x86, 0x58,
];
const TRANSPORT_EXPECTED: [u8; 32] = [
    0xef, 0x78, 0x38, 0xf2, 0xc4, 0x23, 0xbd, 0x70, 0xbe, 0xdc, 0xcb, 0xf4, 0x05, 0x6b, 0xc8, 0xa5,
    0x61, 0xa5, 0xee, 0xcf, 0x34, 0xdb, 0xf4, 0x66, 0xdb, 0x18, 0xab, 0xb3, 0x99, 0x38, 0x37, 0x41,
];
const DEVICE_BOUND_EXPECTED: [u8; 32] = [
    0xd5, 0x93, 0x71, 0xf4, 0xb3, 0x43, 0xc9, 0x02, 0x2e, 0x56, 0x76, 0xad, 0xf0, 0x32, 0xad, 0x97,
    0x4e, 0xfc, 0x8e, 0x1c, 0x76, 0xdd, 0xcc, 0x3a, 0xff, 0xc7, 0x57, 0xdd, 0xa5, 0x5a, 0x47, 0xc5,
];

#[test]
fn argon2id_v19_known_answers_cover_supported_policy_domains() {
    let mut ok = KDF_ID_ARGON2ID == 2;
    ok &=
        derive_key_32(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT) == Ok(PORTABLE_EXPECTED);
    ok &=
        derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT) == Ok(WALLET_EXPECTED);
    ok &= derive_key_32(PasswordKdfPurpose::EncryptedTransport, PASSWORD, &SALT)
        == Ok(TRANSPORT_EXPECTED);
    ok &= derive_key_32(PasswordKdfPurpose::DeviceBoundBackup, PASSWORD, &SALT)
        == Ok(DEVICE_BOUND_EXPECTED);
    assert!(ok);
}

#[test]
fn host_profile_is_v1_with_64_mib_and_matches_the_reference_vector() {
    let host = PasswordKdfParams::host();
    assert_eq!(
        host,
        PasswordKdfParams {
            profile_version: PROFILE_VERSION_2,
            argon_version: ARGON2_VERSION_13,
            m_cost_kib: V2_MEMORY_KIB,
            t_cost: V1_TIME_COST,
            p_cost: V1_PARALLELISM,
        }
    );
    assert_eq!(V2_MEMORY_KIB, 64 * 1024);
    assert_eq!(
        derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, host),
        Ok(PORTABLE_HOST_EXPECTED)
    );
    let metadata = encode_metadata(host).expect("host metadata");
    assert_eq!(parse_metadata(&metadata), Ok(host));
}

#[test]
fn profile_predicates_accept_exactly_the_two_fixed_profiles() {
    let current = PasswordKdfParams::current();
    let host = PasswordKdfParams::host();
    assert!(current.is_current() & !current.is_host() & current.is_supported());
    assert!(host.is_host() & !host.is_current() & host.is_supported());
    // Mixing one profile's version with the other's memory matches neither.
    let mixed = [
        PasswordKdfParams {
            profile_version: PROFILE_VERSION_2,
            ..current
        },
        PasswordKdfParams {
            profile_version: PROFILE_VERSION_1,
            ..host
        },
    ];
    for params in mixed {
        assert!(!params.is_supported(), "{params:?}");
        assert_eq!(
            encode_metadata(params),
            Err(PasswordKdfError::UnsupportedParameters)
        );
    }
    for edit in [
        |p: &mut PasswordKdfParams| p.argon_version -= 1,
        |p: &mut PasswordKdfParams| p.m_cost_kib -= 1,
        |p: &mut PasswordKdfParams| p.t_cost += 1,
        |p: &mut PasswordKdfParams| p.p_cost += 1,
    ] {
        let mut changed = host;
        edit(&mut changed);
        assert!(!changed.is_host() & !changed.is_supported(), "{changed:?}");
    }
}

#[test]
fn current_and_minimum_predicates_cover_every_field() {
    let current = PasswordKdfParams::current();
    let mut ok = current.is_current() & current.meets_v1_minimum();

    let mut changed = current;
    changed.profile_version = PROFILE_VERSION_1 + 1;
    ok &= !changed.is_current();

    changed = current;
    changed.argon_version = ARGON2_VERSION_13 - 1;
    ok &= !changed.is_current() & !changed.meets_v1_minimum();

    changed = current;
    changed.m_cost_kib = V1_MEMORY_KIB - 1;
    ok &= !changed.is_current() & !changed.meets_v1_minimum();

    changed = current;
    changed.t_cost = V1_TIME_COST - 1;
    ok &= !changed.is_current() & !changed.meets_v1_minimum();

    changed = current;
    changed.p_cost = V1_PARALLELISM - 1;
    ok &= !changed.is_current() & !changed.meets_v1_minimum();
    assert!(ok);
}

#[test]
fn allocation_failure_is_fail_closed_without_parameter_downgrade() {
    let parameters = PasswordKdfParams::current();
    let count = V1_MEMORY_KIB as usize;
    let mut ok = workspace_block_count(parameters) == Ok(count);
    let mut workspace = vec![PasswordKdfBlock::default(); count];
    ok &= derive_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        parameters,
        &mut workspace,
    ) == Ok(PORTABLE_EXPECTED);
    ok &= workspace[0].as_mut()[0] == 0;

    let mut short = vec![PasswordKdfBlock::default(); count - 1];
    short[0].as_mut()[0] = 0x55;
    ok &= derive_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        parameters,
        &mut short,
    ) == Err(PasswordKdfError::AllocationFailed);
    ok &= short[0].as_mut()[0] == 0;

    workspace[0].as_mut()[0] = 0xa5;
    zeroize_workspace(&mut workspace);
    ok &= workspace[0].as_mut()[0] == 0;
    zeroize_workspace(&mut []);
    ok &= derive_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        b"",
        &SALT,
        parameters,
        &mut workspace,
    ) == Err(PasswordKdfError::InvalidPasswordLength);
    ok &= parameters.is_current();
    assert!(ok);
}

#[test]
fn purpose_and_salt_are_domain_separated() {
    let portable = derive_key_32(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT);
    let wallet = derive_key_32(PasswordKdfPurpose::PersistentWallet, PASSWORD, &SALT);
    let mut other_salt = SALT;
    other_salt[0] ^= 0x80;
    let other = derive_key_32(PasswordKdfPurpose::PortableBackup, PASSWORD, &other_salt);
    assert!((portable != wallet) & (portable != other));
}

#[test]
fn current_formats_reject_every_parameter_change() {
    let current = PasswordKdfParams::current();
    let rejected = Err(PasswordKdfError::UnsupportedParameters);
    let mut ok = true;

    let mut changed = current;
    changed.profile_version += 1;
    ok &= derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, changed)
        == rejected;
    changed = current;
    changed.argon_version -= 1;
    ok &= derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, changed)
        == rejected;
    changed = current;
    changed.m_cost_kib -= 1;
    ok &= derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, changed)
        == rejected;
    changed = current;
    changed.t_cost -= 1;
    ok &= derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, changed)
        == rejected;
    changed = current;
    changed.p_cost = 0;
    ok &= derive_key_32_with_params(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, changed)
        == rejected;
    assert!(ok);
}

#[test]
fn metadata_roundtrip_rejects_parameter_downgrade_and_unknown_kdf_tamper() {
    let current = PasswordKdfParams::current();
    let encoded = encode_metadata(current);
    let mut ok = encoded.is_ok();
    let metadata = encoded.unwrap_or([0u8; super::METADATA_SIZE]);
    let rejected = Err(PasswordKdfError::UnsupportedParameters);
    ok &= parse_metadata(&metadata) == Ok(current);
    ok &= parse_metadata(&metadata[..11]) == rejected;

    let mut changed = metadata;
    changed[0] = 0xff;
    ok &= parse_metadata(&changed) == rejected;
    changed = metadata;
    changed[1] += 1;
    ok &= parse_metadata(&changed) == rejected;
    changed = metadata;
    changed[2] -= 1;
    ok &= parse_metadata(&changed) == rejected;
    changed = metadata;
    changed[3] = 0;
    ok &= parse_metadata(&changed) == rejected;
    changed = metadata;
    changed[4..8].copy_from_slice(&(V1_MEMORY_KIB - 1).to_le_bytes());
    ok &= parse_metadata(&changed) == rejected;
    changed = metadata;
    changed[8..12].copy_from_slice(&(V1_TIME_COST - 1).to_le_bytes());
    ok &= parse_metadata(&changed) == rejected;
    assert!(ok);
}

#[test]
fn encode_metadata_rejects_non_current_parameters() {
    let mut changed = PasswordKdfParams::current();
    changed.p_cost = 0;
    assert!(encode_metadata(changed) == Err(PasswordKdfError::UnsupportedParameters));
}

#[test]
fn benchmark_input_validation_covers_each_fail_closed_boundary() {
    let current = PasswordKdfParams::current();
    let rejected = Err(PasswordKdfError::UnsupportedParameters);
    let mut ok = validate_benchmark_inputs(PASSWORD, current) == Ok(());
    ok &= validate_benchmark_inputs(b"", current) == rejected;
    ok &= validate_benchmark_inputs(&[b'x'; 129], current) == rejected;

    let mut wrong_profile = current;
    wrong_profile.profile_version += 1;
    ok &= validate_benchmark_inputs(PASSWORD, wrong_profile) == rejected;
    let mut wrong_version = current;
    wrong_version.argon_version -= 1;
    ok &= validate_benchmark_inputs(PASSWORD, wrong_version) == rejected;
    let mut too_small = current;
    too_small.m_cost_kib = 1_023;
    ok &= validate_benchmark_inputs(PASSWORD, too_small) == rejected;
    let mut floor = current;
    floor.m_cost_kib = 1_024;
    ok &= validate_benchmark_inputs(PASSWORD, floor) == Ok(());
    let mut no_iterations = current;
    no_iterations.t_cost = 0;
    ok &= validate_benchmark_inputs(PASSWORD, no_iterations) == rejected;
    let mut no_parallelism = current;
    no_parallelism.p_cost = 0;
    ok &= validate_benchmark_inputs(PASSWORD, no_parallelism) == rejected;
    assert!(ok);
}

#[test]
fn benchmark_entry_points_cover_success_validation_and_workspace_failures() {
    let current = PasswordKdfParams::current();
    let mut ok =
        derive_benchmark_key_32(PasswordKdfPurpose::PortableBackup, PASSWORD, &SALT, current)
            == Ok(PORTABLE_EXPECTED);
    ok &= derive_benchmark_key_32(PasswordKdfPurpose::PortableBackup, b"", &SALT, current)
        == Err(PasswordKdfError::UnsupportedParameters);

    let count = V1_MEMORY_KIB as usize;
    let mut workspace = vec![PasswordKdfBlock::default(); count];
    ok &= derive_benchmark_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        current,
        &mut workspace,
    ) == Ok(PORTABLE_EXPECTED);
    ok &= workspace[0].as_mut()[0] == 0;

    let mut short = vec![PasswordKdfBlock::default(); count - 1];
    ok &= derive_benchmark_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        current,
        &mut short,
    ) == Err(PasswordKdfError::AllocationFailed);
    ok &= derive_benchmark_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        b"",
        &SALT,
        current,
        &mut workspace,
    ) == Err(PasswordKdfError::UnsupportedParameters);

    let mut invalid_geometry = current;
    invalid_geometry.m_cost_kib = 1_024;
    invalid_geometry.p_cost = 129;
    ok &= derive_benchmark_key_32(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        invalid_geometry,
    ) == Err(PasswordKdfError::UnsupportedParameters);
    ok &= derive_benchmark_key_32_with_workspace(
        PasswordKdfPurpose::PortableBackup,
        PASSWORD,
        &SALT,
        invalid_geometry,
        &mut [],
    ) == Err(PasswordKdfError::UnsupportedParameters);
    assert!(ok);
}

#[test]
fn workspace_parameter_builder_rejects_invalid_argon2_geometry() {
    let mut invalid = PasswordKdfParams::current();
    invalid.p_cost = 0;
    assert!(workspace_block_count(invalid) == Err(PasswordKdfError::UnsupportedParameters));
}

#[test]
fn invalid_password_lengths_fail_closed() {
    let rejected = Err(PasswordKdfError::InvalidPasswordLength);
    let empty = derive_key_32(PasswordKdfPurpose::PersistentWallet, b"", &SALT);
    let oversized = derive_key_32(PasswordKdfPurpose::PersistentWallet, &[b'x'; 129], &SALT);
    assert!((empty == rejected) & (oversized == rejected));
}
