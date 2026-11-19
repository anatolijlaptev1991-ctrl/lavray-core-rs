// SPDX-License-Identifier: GPL-3.0-only

//! Побайтовый reader .srs-потока: uvarint, BE-слайсы, байты (varbin Go).

use crate::source::RuleSetParseError;

pub(crate) struct Reader<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl Reader<'_> {
    pub(crate) fn u8(&mut self) -> Result<u8, RuleSetParseError> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| RuleSetParseError::Other("unexpected EOF".into()))?;
        self.pos += 1;
        Ok(b)
    }
    pub(crate) fn uvarint(&mut self) -> Result<u64, RuleSetParseError> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            result |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err(RuleSetParseError::Other("varint overflow".into()));
            }
        }
    }
    pub(crate) fn u64_be(&mut self) -> Result<u64, RuleSetParseError> {
        let b = self.take(8)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(b);
        Ok(u64::from_be_bytes(v))
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&[u8], RuleSetParseError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| RuleSetParseError::Other("unexpected EOF".into()))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    pub(crate) fn skip(&mut self, n: usize) -> Result<(), RuleSetParseError> {
        self.take(n).map(|_| ())
    }
    pub(crate) fn u64_be_slice(&mut self) -> Result<Vec<u64>, RuleSetParseError> {
        let n = self.uvarint_usize()?;
        let mut out = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            out.push(self.u64_be()?);
        }
        Ok(out)
    }
    pub(crate) fn uvarint_usize(&mut self) -> Result<usize, RuleSetParseError> {
        usize::try_from(self.uvarint()?)
            .map_err(|_| RuleSetParseError::Other("varint overflow".into()))
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, RuleSetParseError> {
        let n = self.uvarint_usize()?;
        Ok(self.take(n)?.to_vec())
    }
}
