pub mod address;

pub mod bytes;
pub mod qr_payload;
pub mod serialization;
pub mod utxo;

use core::fmt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub enum NetworkId {
    Mainnet,
    Testnet(u8),
    Simnet,
    Devnet,
}

impl NetworkId {
    // Preserve the existing public API while allowing future testnet suffixes
    // (for example `NetworkId::Testnet(14)`) without a crate release solely to
    // add another enum variant.
    #[allow(non_upper_case_globals)]
    pub const Testnet10: Self = Self::Testnet(10);
    #[allow(non_upper_case_globals)]
    pub const Testnet11: Self = Self::Testnet(11);
    #[allow(non_upper_case_globals)]
    pub const Testnet12: Self = Self::Testnet(12);

    pub const fn address_prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa",
            Self::Simnet => "kaspasim",
            Self::Devnet => "kaspadev",
            Self::Testnet(_) => "kaspatest",
        }
    }

    pub const fn testnet_suffix(self) -> Option<u8> {
        match self {
            Self::Testnet(suffix) => Some(suffix),
            _ => None,
        }
    }

    /// Parse the canonical user-facing Kaspa network names used by the Rust
    /// and browser APIs. Future testnets up through suffix 127 are accepted so
    /// QA/runtime configuration can move to `testnet-14`, etc. without a code
    /// change to this enum.
    pub fn parse(value: &str) -> Result<Self, String> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "mainnet" | "kaspa:mainnet" => return Ok(Self::Mainnet),
            "simnet" | "kaspa:simnet" => return Ok(Self::Simnet),
            "devnet" | "kaspa:devnet" => return Ok(Self::Devnet),
            _ => {}
        }

        let testnet = normalized
            .strip_prefix("kaspa:")
            .unwrap_or(&normalized)
            .strip_prefix("testnet")
            .ok_or_else(|| "unsupported Kaspa network".to_owned())?;
        let suffix = testnet.strip_prefix('-').unwrap_or(testnet);
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("unsupported Kaspa network".to_owned());
        }
        let suffix = suffix
            .parse::<u16>()
            .map_err(|_| "invalid Kaspa testnet suffix".to_owned())?;
        if !(1..=127).contains(&suffix) {
            return Err("Kaspa testnet suffix must be 1..=127".to_owned());
        }
        Ok(Self::Testnet(suffix as u8))
    }

    pub fn canonical_name(self) -> String {
        match self {
            Self::Mainnet => "mainnet".to_owned(),
            Self::Testnet(suffix) => format!("testnet-{suffix}"),
            Self::Simnet => "simnet".to_owned(),
            Self::Devnet => "devnet".to_owned(),
        }
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => f.write_str("Mainnet"),
            Self::Testnet(suffix) => write!(f, "Testnet{suffix}"),
            Self::Simnet => f.write_str("Simnet"),
            Self::Devnet => f.write_str("Devnet"),
        }
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_name())
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Preserve the historical serde representation ("Testnet10", etc.)
        // while extending it naturally to future suffixes such as
        // "Testnet14".
        serializer.serialize_str(&format!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct Amount(u64);
impl Amount {
    pub const fn from_sompi(value: u64) -> Self {
        Self(value)
    }
    pub const fn sompi(self) -> u64 {
        self.0
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct DaaScore(u64);
impl DaaScore {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! hash_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        pub struct $name(pub [u8; 32]);
        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }
    };
}
hash_type!(BlockHash);
hash_type!(TxId);

#[cfg(test)]
mod network_id_tests {
    use super::NetworkId;

    #[test]
    fn future_testnet_suffixes_parse_without_new_enum_variants() {
        let network = NetworkId::parse("testnet-14").expect("future testnet");
        assert_eq!(network, NetworkId::Testnet(14));
        assert_eq!(network.address_prefix(), "kaspatest");
        assert_eq!(network.canonical_name(), "testnet-14");
        assert_eq!(format!("{network:?}"), "Testnet14");
        assert_eq!(serde_json::to_string(&network).unwrap(), "\"Testnet14\"");
        assert_eq!(
            serde_json::from_str::<NetworkId>("\"Testnet14\"").unwrap(),
            network
        );
        assert_eq!(NetworkId::parse("kaspa:testnet-14").unwrap(), network);
    }

    #[test]
    fn legacy_testnet_constants_remain_compatible() {
        assert_eq!(NetworkId::Testnet10, NetworkId::Testnet(10));
        assert_eq!(NetworkId::Testnet11, NetworkId::Testnet(11));
        assert_eq!(NetworkId::Testnet12, NetworkId::Testnet(12));
        assert_eq!(format!("{:?}", NetworkId::Testnet12), "Testnet12");
    }
}
