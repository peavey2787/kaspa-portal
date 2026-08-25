use k256::elliptic_curve::sec1::ToEncodedPoint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hd45AccountKey {
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
    pub parent_fingerprint: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultisigDescriptor {
    Static {
        threshold: u8,
        public_keys: Vec<[u8; 32]>,
    },
    HierarchicalDeterministic45 {
        threshold: u8,
        account_keys: Vec<Hd45AccountKey>,
    },
}

impl MultisigDescriptor {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = descriptor_line(value.trim());
        if value.starts_with("multi_hd45(") && value.ends_with(')') {
            return parse_hd45(&value[11..value.len() - 1]);
        }
        if value.starts_with("multi(") && value.ends_with(')') {
            return parse_static(&value[6..value.len() - 1]);
        }
        Err("Descriptor must be multi(M,...) or multi_hd45(M,...)".into())
    }

    #[must_use]
    pub fn is_hd(&self) -> bool {
        !matches!(self, Self::Static { .. })
    }

    #[must_use]
    pub fn is_hd45(&self) -> bool {
        matches!(self, Self::HierarchicalDeterministic45 { .. })
    }

    #[must_use]
    pub fn participant_count(&self) -> usize {
        match self {
            Self::Static { public_keys, .. } => public_keys.len(),
            Self::HierarchicalDeterministic45 { account_keys, .. } => account_keys.len(),
        }
    }

    #[must_use]
    pub fn threshold(&self) -> u8 {
        match self {
            Self::Static { threshold, .. }
            | Self::HierarchicalDeterministic45 { threshold, .. } => *threshold,
        }
    }

    pub fn public_keys_at(
        &self,
        address_index: u32,
        cosigner: u32,
        chain: u32,
    ) -> Result<Vec<[u8; 32]>, String> {
        match self {
            Self::Static { public_keys, .. } => {
                let mut keys = public_keys.clone();
                keys.sort();
                Ok(keys)
            }
            Self::HierarchicalDeterministic45 { account_keys, .. } => {
                if chain > 1 {
                    return Err("45' multisig chain must be 0 or 1".into());
                }
                account_keys
                    .iter()
                    .map(|entry| derive_45(entry, cosigner, chain, address_index))
                    .collect()
            }
        }
    }

    pub fn bip32_derivations(
        &self,
        address_index: u32,
        cosigner: u32,
        chain: u32,
    ) -> Result<serde_json::Value, String> {
        let Self::HierarchicalDeterministic45 { account_keys, .. } = self else {
            return Ok(serde_json::json!({}));
        };
        if chain > 1 {
            return Err("45' multisig chain must be 0 or 1".into());
        }
        let path = format!("m/45'/111111'/0'/{cosigner}/{chain}/{address_index}");
        let mut map = serde_json::Map::new();
        for entry in account_keys {
            let compressed = derived_45_compressed(entry, cosigner, chain, address_index)?;
            map.insert(
                hex::encode(compressed),
                serde_json::json!({
                    "keyFingerprint": hex::encode(entry.parent_fingerprint),
                    "derivationPath": path,
                }),
            );
        }
        Ok(serde_json::Value::Object(map))
    }
}

fn descriptor_line(value: &str) -> &str {
    value
        .lines()
        .find(|line| {
            let line = line.trim();
            line.starts_with("multi_hd45(") || line.starts_with("multi(")
        })
        .map(str::trim)
        .unwrap_or(value)
}

fn parse_threshold(parts: &[&str]) -> Result<u8, String> {
    if parts.len() < 3 {
        return Err("Need at least M and 2 cosigners".into());
    }
    let threshold = parts[0]
        .trim()
        .parse::<u8>()
        .map_err(|_| "Invalid M value in descriptor".to_string())?;
    if threshold == 0 || threshold as usize > parts.len() - 1 {
        return Err(format!("Invalid M={} for N={}", threshold, parts.len() - 1));
    }
    Ok(threshold)
}

fn parse_static(inner: &str) -> Result<MultisigDescriptor, String> {
    let parts = inner.split(',').collect::<Vec<_>>();
    let threshold = parse_threshold(&parts)?;
    let mut public_keys = Vec::with_capacity(parts.len() - 1);
    for value in &parts[1..] {
        let value = value.trim();
        if value.len() != 64 {
            return Err(format!("Pubkey must be 64 hex chars, got {}", value.len()));
        }
        let bytes = hex::decode(value).map_err(|error| format!("Invalid pubkey hex: {error}"))?;
        public_keys.push(
            bytes.try_into().map_err(|bytes: Vec<u8>| {
                format!("Pubkey must be 32 bytes, got {}", bytes.len())
            })?,
        );
    }
    Ok(MultisigDescriptor::Static {
        threshold,
        public_keys,
    })
}

fn parse_hd45(inner: &str) -> Result<MultisigDescriptor, String> {
    let parts = inner.split(',').collect::<Vec<_>>();
    let threshold = parse_threshold(&parts)?;
    let encoded = sorted_unique_kpubs(&parts[1..])?;
    let mut account_keys = Vec::with_capacity(encoded.len());
    for kpub in encoded {
        account_keys.push(parse_hd45_account_key(kpub)?);
    }
    Ok(MultisigDescriptor::HierarchicalDeterministic45 {
        threshold,
        account_keys,
    })
}

fn sorted_unique_kpubs<'a>(parts: &'a [&str]) -> Result<Vec<&'a str>, String> {
    let mut encoded = parts.iter().map(|value| value.trim()).collect::<Vec<_>>();
    encoded.sort_unstable();
    if encoded.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Duplicate cosigner kpub in descriptor".into());
    }
    Ok(encoded)
}

fn parse_hd45_account_key(kpub: &str) -> Result<Hd45AccountKey, String> {
    let mut payload = [0u8; crate::wallet::key::account::ACCOUNT_KEY_PAYLOAD_LEN];
    crate::wallet::key::xpub::decode_kpub_or_xpub(kpub.as_bytes(), &mut payload)
        .map_err(|_| "Invalid 45' cosigner account key".to_string())?;
    if payload[4] != 3 {
        return Err("45' cosigner kpub must be an account key at depth 3".into());
    }
    let public_key: [u8; 33] = payload[45..78]
        .try_into()
        .map_err(|_| "Invalid kpub public key".to_string())?;
    k256::PublicKey::from_sec1_bytes(&public_key)
        .map_err(|error| format!("Invalid compressed pubkey: {error}"))?;
    Ok(Hd45AccountKey {
        public_key,
        chain_code: payload[13..45]
            .try_into()
            .map_err(|_| "Invalid kpub chain code".to_string())?,
        parent_fingerprint: payload[5..9]
            .try_into()
            .map_err(|_| "Invalid kpub fingerprint".to_string())?,
    })
}

fn parent(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
) -> Result<crate::wallet::account::derivation::ExtPubKey, String> {
    Ok(crate::wallet::account::derivation::ExtPubKey {
        key: k256::PublicKey::from_sec1_bytes(public_key)
            .map_err(|error| format!("Invalid compressed pubkey: {error}"))?,
        chain_code: *chain_code,
        depth: 3,
    })
}

fn derived_45_compressed(
    entry: &Hd45AccountKey,
    cosigner: u32,
    chain: u32,
    address_index: u32,
) -> Result<[u8; 33], String> {
    let child = parent(&entry.public_key, &entry.chain_code)?
        .derive_child(cosigner)?
        .derive_child(chain)?
        .derive_child(address_index)?;
    child
        .key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| "Derived public key has invalid length".to_string())
}

fn derive_45(
    entry: &Hd45AccountKey,
    cosigner: u32,
    chain: u32,
    address_index: u32,
) -> Result<[u8; 32], String> {
    let compressed = derived_45_compressed(entry, cosigner, chain, address_index)?;
    compressed[1..33]
        .try_into()
        .map_err(|_| "Derived public key has invalid length".to_string())
}
