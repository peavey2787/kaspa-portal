// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

pub(crate) struct KsptReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> KsptReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "KSPT truncated: want {} bytes at pos {}, only {} remain",
                n,
                self.pos,
                self.buf.len() - self.pos
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }
    pub(crate) fn u16_le(&mut self) -> Result<u16, String> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub(crate) fn u32_le(&mut self) -> Result<u32, String> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub(crate) fn u64_le(&mut self) -> Result<u64, String> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub(crate) fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }
    pub(crate) fn compact_script_len(&mut self) -> Result<usize, String> {
        let first = self.u8()?;
        if first == 0xFF {
            Ok(self.u16_le()? as usize)
        } else {
            Ok(first as usize)
        }
    }
}
