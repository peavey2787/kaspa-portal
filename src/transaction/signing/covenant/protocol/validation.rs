use super::{
    BindingHint, CovenantSignResponse, KnownScheme, ProtocolError, RequestKind, ResponseKind,
    MAX_CONTEXT_LEN, MAX_SCRIPT_LEN, REQUEST_HEADER_LEN, REQUEST_MAGIC, SESSION_ID_LEN, VERSION,
};

pub(super) fn validate_request_prefix(input: &[u8]) -> Result<(), ProtocolError> {
    if input.len() < REQUEST_HEADER_LEN || !input.starts_with(&REQUEST_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(())
}

pub(super) fn validate_lengths(script_len: usize, context_len: usize) -> Result<(), ProtocolError> {
    if script_len > MAX_SCRIPT_LEN || context_len > MAX_CONTEXT_LEN {
        Err(ProtocolError::InvalidLength)
    } else {
        Ok(())
    }
}

pub(super) fn request_total_len(
    script_len: usize,
    context_len: usize,
) -> Result<usize, ProtocolError> {
    REQUEST_HEADER_LEN
        .checked_add(script_len)
        .and_then(|value| value.checked_add(context_len))
        .ok_or(ProtocolError::InvalidLength)
}

#[derive(Clone, Copy)]
pub(super) struct RequestValidationFields<'a> {
    pub(super) kind: RequestKind,
    pub(super) scheme: KnownScheme,
    pub(super) binding: BindingHint,
    pub(super) session_id: &'a [u8; SESSION_ID_LEN],
    pub(super) host_commitment: &'a [u8; 32],
    pub(super) key_id: &'a [u8; 32],
    pub(super) binding_token: &'a [u8; 32],
    pub(super) commitment: &'a [u8; 32],
    pub(super) script_len: usize,
    pub(super) context_len: usize,
}

pub(super) fn validate_fields(fields: RequestValidationFields<'_>) -> Result<(), ProtocolError> {
    match fields.kind {
        RequestKind::KeyInfo => validate_key_info_fields(fields),
        RequestKind::Bind => validate_bind_fields(fields),
        RequestKind::Known => validate_known_fields(fields),
        RequestKind::Opaque => validate_opaque_fields(fields),
    }
}

fn validate_key_info_fields(fields: RequestValidationFields<'_>) -> Result<(), ProtocolError> {
    let valid = fields.scheme == KnownScheme::None
        && fields.binding == BindingHint::None
        && *fields.session_id == [0u8; SESSION_ID_LEN]
        && *fields.host_commitment == [0u8; 32]
        && *fields.key_id == [0u8; 32]
        && *fields.binding_token == [0u8; 32]
        && *fields.commitment == [0u8; 32]
        && fields.script_len == 0
        && fields.context_len == 0;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_bind_fields(fields: RequestValidationFields<'_>) -> Result<(), ProtocolError> {
    let base = *fields.session_id == [0u8; SESSION_ID_LEN]
        && *fields.host_commitment == [0u8; 32]
        && *fields.key_id != [0u8; 32]
        && *fields.binding_token == [0u8; 32]
        && fields.script_len != 0;
    let shape = if fields.scheme == KnownScheme::None {
        matches!(fields.binding, BindingHint::None | BindingHint::KeyPresent)
            && *fields.commitment == [0u8; 32]
            && fields.context_len == 0
    } else {
        fields.binding == expected_known_binding(fields.scheme) && fields.context_len != 0
    };
    (base && shape)
        .then_some(())
        .ok_or(ProtocolError::InvalidFields)
}

fn validate_known_fields(fields: RequestValidationFields<'_>) -> Result<(), ProtocolError> {
    let valid = fields.scheme != KnownScheme::None
        && fields.binding == expected_known_binding(fields.scheme)
        && *fields.session_id != [0u8; SESSION_ID_LEN]
        && *fields.host_commitment != [0u8; 32]
        && *fields.key_id != [0u8; 32]
        && *fields.binding_token != [0u8; 32]
        && fields.script_len != 0
        && fields.context_len != 0;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_opaque_fields(fields: RequestValidationFields<'_>) -> Result<(), ProtocolError> {
    let valid = fields.scheme == KnownScheme::None
        && matches!(fields.binding, BindingHint::None | BindingHint::KeyPresent)
        && *fields.session_id != [0u8; SESSION_ID_LEN]
        && *fields.host_commitment != [0u8; 32]
        && *fields.key_id != [0u8; 32]
        && *fields.binding_token != [0u8; 32]
        && fields.script_len != 0
        && fields.context_len == 0;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

pub(super) fn validate_response(response: &CovenantSignResponse) -> Result<(), ProtocolError> {
    if response.key_id == [0u8; 32] || response.pubkey_x == [0u8; 32] {
        return Err(ProtocolError::InvalidFields);
    }
    response_shape_valid(response)
        .then_some(())
        .ok_or(ProtocolError::InvalidFields)
}

pub(super) fn response_shape_valid(response: &CovenantSignResponse) -> bool {
    match response.kind {
        ResponseKind::KeyInfo => key_info_response_valid(response),
        ResponseKind::Binding => binding_response_valid(response),
        ResponseKind::NonceCommitment => nonce_response_valid(response),
        ResponseKind::Signature => signature_response_valid(response),
    }
}

pub(super) fn key_info_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id == [0u8; SESSION_ID_LEN]
        && response.binding_token == [0u8; 32]
        && response.commitment == [0u8; 32]
        && response.nonce_point == [0u8; 33]
        && response.signature == [0u8; 64]
}

pub(super) fn binding_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id == [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.commitment != [0u8; 32]
        && response.nonce_point == [0u8; 33]
        && response.signature == [0u8; 64]
}

pub(super) fn nonce_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id != [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.nonce_point[0] == 0x02
        && response.signature == [0u8; 64]
}

pub(super) fn signature_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id != [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.nonce_point[0] == 0x02
        && response.signature != [0u8; 64]
}

pub(super) fn valid_review_context<'a>(
    context: &'a [u8],
    max_len: usize,
    prefix: Option<&[u8]>,
) -> Option<&'a [u8]> {
    if context.is_empty() || context.len() > max_len {
        return None;
    }
    core::str::from_utf8(context).ok()?;
    if !context.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return None;
    }
    if prefix.is_some_and(|expected| !context.starts_with(expected)) {
        return None;
    }
    Some(context)
}

#[must_use]
pub const fn expected_known_binding(scheme: KnownScheme) -> BindingHint {
    match scheme {
        KnownScheme::Sha256Preimage | KnownScheme::OracleV1 => BindingHint::FixedCheckSigFromStack,
        KnownScheme::None => BindingHint::None,
    }
}

pub(super) fn parse_kind(value: u8) -> Result<RequestKind, ProtocolError> {
    match value {
        0 => Ok(RequestKind::KeyInfo),
        1 => Ok(RequestKind::Known),
        2 => Ok(RequestKind::Opaque),
        3 => Ok(RequestKind::Bind),
        _ => Err(ProtocolError::InvalidKind),
    }
}

pub(super) fn parse_scheme(value: u8) -> Result<KnownScheme, ProtocolError> {
    match value {
        0 => Ok(KnownScheme::None),
        1 => Ok(KnownScheme::Sha256Preimage),
        2 => Ok(KnownScheme::OracleV1),
        _ => Err(ProtocolError::InvalidScheme),
    }
}
pub(super) fn parse_binding(value: u8) -> Result<BindingHint, ProtocolError> {
    match value {
        0 => Ok(BindingHint::None),
        1 => Ok(BindingHint::KeyPresent),
        2 => Ok(BindingHint::FixedCheckSigFromStack),
        _ => Err(ProtocolError::InvalidBinding),
    }
}
pub(super) fn array16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}
pub(super) fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}
