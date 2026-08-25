//! Canonical Kaspa address encoding, decoding, validation, and script conversion.
//! This low-level module is shared by network, wallet, transaction, and contract code.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHECKSUM_LEN: usize = 8;
const GEN: [u64; 5] = [
    0x98f2_bc8e61,
    0x79b7_6d99e2,
    0xf33e_5fb3c4,
    0xae2e_abe2a8,
    0x1e4f_43e470,
];

pub const MAX_ADDR_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    P2pk = 0x00,
    P2pkEcdsa = 0x01,
    P2sh = 0x08,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KaspaNetwork {
    Unknown = 0,
    Mainnet = 1,
    Testnet = 2,
    Devnet = 3,
    Simnet = 4,
}

impl KaspaNetwork {
    pub const fn hrp(self) -> Option<&'static str> {
        match self {
            Self::Unknown => None,
            Self::Mainnet => Some("kaspa"),
            Self::Testnet => Some("kaspatest"),
            Self::Devnet => Some("kaspadev"),
            Self::Simnet => Some("kaspasim"),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "NETWORK UNKNOWN",
            Self::Mainnet => "MAINNET",
            Self::Testnet => "TESTNET",
            Self::Devnet => "DEVNET",
            Self::Simnet => "SIMNET",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "mainnet" => Some(Self::Mainnet),
            "testnet" | "kaspatest" => Some(Self::Testnet),
            "devnet" | "kaspadev" => Some(Self::Devnet),
            "simnet" | "kaspasim" => Some(Self::Simnet),
            value if value.starts_with("testnet") => Some(Self::Testnet),
            _ => None,
        }
    }

    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet),
            3 => Some(Self::Devnet),
            4 => Some(Self::Simnet),
            _ => None,
        }
    }
}

pub fn encode_p2pk_address(pubkey: &[u8; 32], prefix: &str) -> String {
    encode_address_text(pubkey, AddressType::P2pk as u8, prefix)
}

pub fn encode_p2sh_address(script_hash: &[u8; 32], prefix: &str) -> String {
    encode_address_text(script_hash, AddressType::P2sh as u8, prefix)
}

#[must_use]
pub fn script_hash(redeem_script: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(redeem_script);
    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

pub fn script_to_p2sh_address(redeem_script: &[u8], prefix: &str) -> String {
    encode_p2sh_address(&script_hash(redeem_script), prefix)
}

pub fn encode_address_for_network(
    pubkey: &[u8],
    addr_type: AddressType,
    network: KaspaNetwork,
    out: &mut [u8; MAX_ADDR_LEN],
) -> usize {
    let Some(prefix) = network.hrp() else {
        return 0;
    };
    if !valid_payload_length(addr_type as u8, pubkey.len()) {
        return 0;
    }
    let text = encode_address_bytes(pubkey, addr_type as u8, prefix);
    if text.len() > out.len() {
        return 0;
    }
    out[..text.len()].copy_from_slice(text.as_bytes());
    text.len()
}

pub fn encode_address(
    pubkey: &[u8],
    addr_type: AddressType,
    out: &mut [u8; MAX_ADDR_LEN],
) -> usize {
    encode_address_for_network(pubkey, addr_type, KaspaNetwork::Mainnet, out)
}

pub fn encode_p2pk(pubkey: &[u8; 32], out: &mut [u8; MAX_ADDR_LEN]) -> usize {
    encode_address(pubkey, AddressType::P2pk, out)
}

pub fn encode_address_str_for_network<'a>(
    pubkey: &[u8; 32],
    addr_type: AddressType,
    network: KaspaNetwork,
    out: &'a mut [u8; MAX_ADDR_LEN],
) -> &'a str {
    let len = encode_address_for_network(pubkey, addr_type, network, out);
    core::str::from_utf8(&out[..len]).unwrap_or("address:error")
}

pub fn encode_address_str<'a>(
    pubkey: &[u8; 32],
    addr_type: AddressType,
    out: &'a mut [u8; MAX_ADDR_LEN],
) -> &'a str {
    encode_address_str_for_network(pubkey, addr_type, KaspaNetwork::Mainnet, out)
}

pub fn decode_address(addr: &str) -> Result<(u8, [u8; 32]), String> {
    let decoded = decode_address_bytes(addr)?;
    if decoded.payload.len() != 32 {
        return Err(format!(
            "Address payload length {} is not supported by this decoder",
            decoded.payload.len()
        ));
    }
    let mut payload = [0u8; 32];
    payload.copy_from_slice(&decoded.payload);
    Ok((decoded.version, payload))
}

pub fn validate_kaspa_address(addr: &[u8]) -> bool {
    core::str::from_utf8(addr)
        .ok()
        .and_then(|text| decode_address_bytes(text).ok())
        .is_some()
}

pub fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, String> {
    let decoded = decode_address_bytes(addr)?;
    match decoded.version {
        0x00 if decoded.payload.len() == 32 => {
            let mut script = Vec::with_capacity(34);
            script.push(0x20);
            script.extend_from_slice(&decoded.payload);
            script.push(0xac);
            Ok(script)
        }
        0x08 if decoded.payload.len() == 32 => {
            let mut script = Vec::with_capacity(35);
            script.extend_from_slice(&[0xaa, 0x20]);
            script.extend_from_slice(&decoded.payload);
            script.push(0x87);
            Ok(script)
        }
        0x00 | 0x08 => Err(format!(
            "Invalid payload length {} for address version {:#x}",
            decoded.payload.len(),
            decoded.version
        )),
        version => Err(format!("Unknown version: {version:#x}")),
    }
}

struct DecodedAddress {
    version: u8,
    payload: Vec<u8>,
}

fn decode_address_bytes(addr: &str) -> Result<DecodedAddress, String> {
    let (prefix, data_part) = split_address(addr)?;
    let values = decode_chars(data_part)?;
    if values.len() <= CHECKSUM_LEN {
        return Err("Address too short".into());
    }
    verify_checksum(prefix, &values)?;
    let payload_values = &values[..values.len() - CHECKSUM_LEN];
    let decoded = convert_bits(payload_values, 5, 8, false)?;
    let Some((&version, payload)) = decoded.split_first() else {
        return Err("Address payload is empty".into());
    };
    if !valid_payload_length(version, payload.len()) {
        return Err(format!(
            "Invalid payload length {} for address version {version:#x}",
            payload.len()
        ));
    }
    Ok(DecodedAddress {
        version,
        payload: payload.to_vec(),
    })
}

fn valid_payload_length(version: u8, payload_len: usize) -> bool {
    match version {
        0x00 | 0x08 => payload_len == 32,
        0x01 => payload_len == 33,
        _ => payload_len == 32 || payload_len == 33,
    }
}

fn encode_address_text(payload: &[u8; 32], version: u8, prefix: &str) -> String {
    encode_address_bytes(payload, version, prefix)
}

fn encode_address_bytes(payload: &[u8], version: u8, prefix: &str) -> String {
    let mut bytes = Vec::with_capacity(payload.len() + 1);
    bytes.push(version);
    bytes.extend_from_slice(payload);
    let data = convert_bits(&bytes, 8, 5, true).expect("8-to-5 conversion cannot fail");
    let checksum = create_checksum(prefix, &data);

    let mut result = String::with_capacity(prefix.len() + 1 + data.len() + CHECKSUM_LEN);
    result.push_str(prefix);
    result.push(':');
    for value in data {
        result.push(CHARSET[value as usize] as char);
    }
    for index in 0..CHECKSUM_LEN {
        let shift = 5 * (CHECKSUM_LEN - 1 - index);
        result.push(CHARSET[((checksum >> shift) & 0x1f) as usize] as char);
    }
    result
}

fn split_address(addr: &str) -> Result<(&str, &str), String> {
    let Some((prefix, data)) = addr.split_once(':') else {
        return Err("Unknown address prefix".into());
    };
    if !matches!(prefix, "kaspa" | "kaspatest" | "kaspasim" | "kaspadev") {
        return Err("Unknown address prefix".into());
    }
    if data.len() < 9 {
        return Err("Address too short".into());
    }
    Ok((prefix, data))
}

fn decode_chars(data: &str) -> Result<Vec<u8>, String> {
    data.bytes().map(decode_char).collect()
}

fn decode_char(byte: u8) -> Result<u8, String> {
    CHARSET
        .iter()
        .position(|&candidate| candidate == byte)
        .map(|index| index as u8)
        .ok_or_else(|| format!("Invalid character: '{}'", byte as char))
}

fn verify_checksum(prefix: &str, values: &[u8]) -> Result<(), String> {
    let mut stream = Vec::with_capacity(prefix.len() + 1 + values.len());
    stream.extend(prefix.bytes().map(|byte| byte & 0x1f));
    stream.push(0);
    stream.extend_from_slice(values);
    if polymod(stream.into_iter()) == 1 {
        Ok(())
    } else {
        Err("Checksum mismatch".into())
    }
}

fn create_checksum(prefix: &str, payload: &[u8]) -> u64 {
    let values = prefix
        .bytes()
        .map(|byte| byte & 0x1f)
        .chain([0])
        .chain(payload.iter().copied())
        .chain([0; CHECKSUM_LEN]);
    polymod(values) ^ 1
}

fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    let mut checksum = 1u64;
    for value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x0007_ffff_ffff) << 5) ^ u64::from(value);
        for (index, generator) in GEN.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn convert_bits(data: &[u8], from: u8, to: u8, pad: bool) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity((data.len() * usize::from(from)).div_ceil(usize::from(to)));
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let max_value = (1u32 << to) - 1;
    let max_accumulator = (1u32 << (from + to - 1)) - 1;

    for &value in data {
        if (u32::from(value) >> from) != 0 {
            return Err("Invalid address data value".into());
        }
        accumulator = ((accumulator << from) | u32::from(value)) & max_accumulator;
        bits += from;
        while bits >= to {
            bits -= to;
            output.push(((accumulator >> bits) & max_value) as u8);
        }
    }

    if pad {
        if bits > 0 {
            output.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return Err("Invalid address padding".into());
    }

    Ok(output)
}

#[cfg(test)]
#[path = "unit-tests/address_tests.rs"]
mod unit_tests;
