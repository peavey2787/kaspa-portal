use alloc::vec;

use super::{
    derive_benchmark_key_32, derive_benchmark_key_32_with_workspace, derive_key_32,
    derive_key_32_with_params, derive_key_32_with_workspace, encode_metadata, parse_metadata,
    validate_benchmark_inputs, workspace_block_count, zeroize_workspace, PasswordKdfBlock,
    PasswordKdfError, PasswordKdfParams, PasswordKdfPurpose, ARGON2_VERSION_13, KDF_ID_ARGON2ID,
    PROFILE_VERSION_1, V1_MEMORY_KIB, V1_PARALLELISM, V1_TIME_COST,
};

const PASSWORD: &[u8] = b"CorrectHorse9";
const SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const PORTABLE_EXPECTED: [u8; 32] = [
    0xa7, 0x89, 0x77, 0x18, 0x15, 0xe2, 0xef, 0xc0, 0x52, 0xf9, 0x4f, 0x8f, 0x38, 0x68, 0x0e, 0xa8,
    0x3a, 0x62, 0x61, 0x64, 0x80, 0xa3, 0x57, 0xf0, 0x69, 0xf3, 0x3e, 0xa8, 0xa3, 0x95, 0x88, 0x69,
];
const WALLET_EXPECTED: [u8; 32] = [
    0x25, 0xb6, 0xbe, 0xff, 0x65, 0xa5, 0xd5, 0x3b, 0x43, 0x15, 0x28, 0x5d, 0x60, 0x7c, 0xb2, 0xaa,
    0x4e, 0xa7, 0x10, 0x77, 0x3e, 0x8d, 0x03, 0x3b, 0x21, 0x57, 0xeb, 0x32, 0x51, 0x45, 0x58, 0xda,
];
const TRANSPORT_EXPECTED: [u8; 32] = [
    0x52, 0xc0, 0xab, 0x5b, 0xc4, 0xa7, 0x58, 0x9a, 0x9f, 0x13, 0xe3, 0x89, 0x38, 0x33, 0x69, 0x15,
    0x4b, 0x05, 0xb1, 0x87, 0x55, 0xca, 0x6b, 0xc3, 0x59, 0xd8, 0x66, 0xea, 0x33, 0x59, 0x8c, 0xc7,
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
    assert!(ok);
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
