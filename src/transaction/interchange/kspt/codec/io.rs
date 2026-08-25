use crate::transaction::model::Hash256;

use super::super::error::PsktError;

pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn peek_u8(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub(crate) fn finish(self) -> Result<(), PsktError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(PsktError::TrailingData)
        }
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, PsktError> {
        if self.pos >= self.data.len() {
            return Err(PsktError::BufferTooShort);
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    pub(crate) fn read_u16_le(&mut self) -> Result<u16, PsktError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// SPK length: one byte, or `0xff` followed by a little-endian `u16`.
    pub(crate) fn read_spk_len(&mut self) -> Result<usize, PsktError> {
        let prefix = self.read_u8()?;
        if prefix == 0xff {
            Ok(self.read_u16_le()? as usize)
        } else {
            Ok(prefix as usize)
        }
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32, PsktError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64_le(&mut self) -> Result<u64, PsktError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], PsktError> {
        if self.remaining() < count {
            return Err(PsktError::BufferTooShort);
        }
        let bytes = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(bytes)
    }

    pub(crate) fn read_hash256(&mut self) -> Result<Hash256, PsktError> {
        let bytes = self.read_bytes(32)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Ok(hash)
    }
}

pub(crate) struct ByteWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ByteWriter<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) const fn written(&self) -> usize {
        self.pos
    }

    pub(crate) fn write_bytes(&mut self, data: &[u8]) -> Result<(), PsktError> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(PsktError::OutputBufferTooSmall)?;
        let destination = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(PsktError::OutputBufferTooSmall)?;
        destination.copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub(crate) fn write_u8(&mut self, value: u8) -> Result<(), PsktError> {
        self.write_bytes(&[value])
    }

    pub(crate) fn write_u16_le(&mut self, value: u16) -> Result<(), PsktError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub(crate) fn write_u32_le(&mut self, value: u32) -> Result<(), PsktError> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub(crate) fn write_spk_len(&mut self, len: usize) -> Result<(), PsktError> {
        if len <= 254 {
            self.write_u8(len as u8)
        } else {
            self.write_u8(0xff)?;
            self.write_u16_le(len as u16)
        }
    }

    pub(crate) fn write_u64_le(&mut self, value: u64) -> Result<(), PsktError> {
        self.write_bytes(&value.to_le_bytes())
    }
}
