use serde::{Deserialize, Serialize};

pub const BEACON_PROOF_VERSION: u16 = 1;

use crate::{
    error::{Error, Result},
    primitives::NetworkId,
    randomness::{
        extractor::{canonical_evidence, extract_and_fold, ExtractorConfig},
        source::{
            curby::{CurbyClient, CurbyEvidence, CurbyVerification},
            kaspa::{KaspaBlockBuffer, KaspaEntropyEvidence},
        },
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconRequest {
    pub network: NetworkId,
    #[serde(default)]
    pub context: Vec<u8>,
    pub kaspa: Vec<KaspaEntropyEvidence>,
    pub curby: Option<CurbyEvidence>,
    #[serde(default)]
    pub extractor: ExtractorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconProof {
    pub version: u16,
    pub network: NetworkId,
    pub context: Vec<u8>,
    pub kaspa: Vec<KaspaEntropyEvidence>,
    pub curby: Option<CurbyEvidence>,
    pub extractor: ExtractorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconResult {
    pub output: [u8; 32],
    pub proof: BeaconProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeaconVerification {
    pub valid: bool,
    pub output: [u8; 32],
    pub uses_curby: bool,
    /// True only when the evidence explicitly records independent CURBy
    /// protocol verification. A successful raw HTTPS API response alone does
    /// not establish this property.
    pub curby_source_verified: bool,
    pub kaspa_evidence_finalized: bool,
}

#[derive(Clone)]
pub struct BeaconApi {
    kaspa: KaspaBlockBuffer,
    curby: CurbyClient,
}

impl BeaconApi {
    pub(crate) fn new(curby: CurbyClient) -> Self {
        Self {
            kaspa: KaspaBlockBuffer::default(),
            curby,
        }
    }

    pub fn observe_kaspa_block(&self, evidence: KaspaEntropyEvidence) -> Result<()> {
        self.kaspa.push(evidence).map_err(Error::Beacon)
    }

    pub fn generate(&self, request: BeaconRequest) -> Result<BeaconResult> {
        generate(request).map_err(Error::Beacon)
    }

    pub fn verify(&self, result: &BeaconResult) -> Result<BeaconVerification> {
        verify_result(result).map_err(Error::Beacon)
    }

    pub async fn generate_live(
        &self,
        network: NetworkId,
        kaspa_blocks: usize,
        use_curby: bool,
        context: Vec<u8>,
    ) -> Result<BeaconResult> {
        let kaspa = self.kaspa.recent(kaspa_blocks).map_err(Error::Beacon)?;
        let curby = if use_curby {
            Some(self.curby.latest().await.map_err(Error::Beacon)?)
        } else {
            None
        };
        self.generate(BeaconRequest {
            network,
            context,
            kaspa,
            curby,
            extractor: ExtractorConfig::default(),
        })
    }
}

fn generate(request: BeaconRequest) -> core::result::Result<BeaconResult, String> {
    validate_request(&request)?;
    let evidence = canonical_evidence(request.network, &request.kaspa, request.curby.as_ref())?;
    let output = extract_and_fold(&evidence.bytes, &request.context, request.extractor)?;
    Ok(BeaconResult {
        output,
        proof: BeaconProof {
            version: BEACON_PROOF_VERSION,
            network: request.network,
            context: request.context,
            kaspa: request.kaspa,
            curby: request.curby,
            extractor: request.extractor,
        },
    })
}

pub fn verify_result(result: &BeaconResult) -> core::result::Result<BeaconVerification, String> {
    if result.proof.version != BEACON_PROOF_VERSION {
        return Err("unsupported beacon proof version".into());
    }
    let rebuilt = generate(BeaconRequest {
        network: result.proof.network,
        context: result.proof.context.clone(),
        kaspa: result.proof.kaspa.clone(),
        curby: result.proof.curby.clone(),
        extractor: result.proof.extractor,
    })?;
    let valid: bool =
        subtle::ConstantTimeEq::ct_eq(rebuilt.output.as_slice(), result.output.as_slice()).into();
    Ok(BeaconVerification {
        valid,
        output: rebuilt.output,
        uses_curby: result.proof.curby.is_some(),
        curby_source_verified: result
            .proof
            .curby
            .as_ref()
            .map(|value| matches!(value.verification, CurbyVerification::ExternallyVerified))
            .unwrap_or(false),
        kaspa_evidence_finalized: result.proof.kaspa.iter().all(|value| value.finalized),
    })
}

fn validate_request(request: &BeaconRequest) -> core::result::Result<(), String> {
    if request.context.len() > 4096 {
        return Err("beacon context exceeds 4096 bytes".into());
    }
    if request.kaspa.is_empty() {
        return Err("beacon requires at least one finalized Kaspa block hash".into());
    }
    if request.kaspa.len() > 256 {
        return Err("beacon accepts at most 256 Kaspa blocks".into());
    }
    for evidence in &request.kaspa {
        evidence.validate()?;
    }
    request.extractor.validate()
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
