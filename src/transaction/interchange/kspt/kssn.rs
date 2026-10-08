use alloc::vec::Vec;

use crate::transaction::model::SigHashType;

use super::{
    error::PsktError,
    format::{KSSN_MAGIC, KSSN_VERSION_CURRENT},
    wire::io::{Reader, Writer},
};

#[derive(Debug, Clone)]
pub struct InputSignature {
    pub input_index: u32,
    pub sighash_type: SigHashType,
    pub signature: [u8; 64],
}

#[derive(Debug, Default)]
pub struct SignedResponse {
    pub signatures: Vec<InputSignature>,
}

fn read_response_count(reader: &mut Reader<'_>) -> Result<usize, PsktError> {
    if reader.bytes(4)? != KSSN_MAGIC {
        return Err(PsktError::InvalidMagic);
    }
    if reader.u8()? != KSSN_VERSION_CURRENT {
        return Err(PsktError::UnsupportedVersion);
    }
    usize::try_from(reader.u32()?).map_err(|_| PsktError::TooManySignatures)
}

fn read_input_signature(reader: &mut Reader<'_>) -> Result<InputSignature, PsktError> {
    let input_index = reader.u32()?;
    let sighash_type = SigHashType::from_byte(reader.u8()?).ok_or(PsktError::InvalidSigHashType)?;
    let signature = reader.array::<64>()?;
    Ok(InputSignature {
        input_index,
        sighash_type,
        signature,
    })
}

impl SignedResponse {
    pub const fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn add_signature(
        &mut self,
        input_index: u32,
        sighash_type: SigHashType,
        signature: &[u8; 64],
    ) -> Result<(), PsktError> {
        if self
            .signatures
            .iter()
            .any(|existing| existing.input_index == input_index)
        {
            return Err(PsktError::InvalidSignatureState);
        }
        self.signatures
            .try_reserve(1)
            .map_err(|_| PsktError::TooManySignatures)?;
        self.signatures.push(InputSignature {
            input_index,
            sighash_type,
            signature: *signature,
        });
        Ok(())
    }

    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, PsktError> {
        let count =
            u32::try_from(self.signatures.len()).map_err(|_| PsktError::TooManySignatures)?;
        let mut writer = Writer::new(output);
        writer.bytes(&KSSN_MAGIC)?;
        writer.u8(KSSN_VERSION_CURRENT)?;
        writer.u32(count)?;
        for signature in &self.signatures {
            writer.u32(signature.input_index)?;
            writer.u8(signature.sighash_type.to_byte())?;
            writer.bytes(&signature.signature)?;
        }
        Ok(writer.written())
    }

    pub fn parse(data: &[u8]) -> Result<Self, PsktError> {
        let mut reader = Reader::new(data);
        let count = read_response_count(&mut reader)?;
        let mut response = Self {
            signatures: Vec::new(),
        };
        response
            .signatures
            .try_reserve(count)
            .map_err(|_| PsktError::TooManySignatures)?;
        for _ in 0..count {
            let input = read_input_signature(&mut reader)?;
            response.add_signature(input.input_index, input.sighash_type, &input.signature)?;
        }
        if reader.remaining() != 0 {
            return Err(PsktError::TrailingData);
        }
        Ok(response)
    }
}
