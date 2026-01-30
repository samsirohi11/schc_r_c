//! BitBuffer Abstraction
//!
//! Provides a position-tracked bit-level read/write buffer wrapping `bitvec`,
//! replacing ad-hoc bit manipulation in compressor/decompressor.

use bitvec::prelude::*;

/// A position-tracked bit-level read/write buffer.
pub struct BitBuffer {
    bits: BitVec<u8, Msb0>,
    position: usize,
}

impl BitBuffer {
    /// Create a new empty BitBuffer.
    pub fn new() -> Self {
        Self {
            bits: BitVec::new(),
            position: 0,
        }
    }

    /// Create a BitBuffer from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bits: BitVec::from_slice(bytes),
            position: 0,
        }
    }

    /// Read a single bit and advance position.
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.position >= self.bits.len() {
            return None;
        }
        let bit = self.bits[self.position];
        self.position += 1;
        Some(bit)
    }

    /// Read n bits as a u64 value (MSB first) and advance position.
    pub fn read_bits(&mut self, n: usize) -> Option<u64> {
        if self.position + n > self.bits.len() || n > 64 {
            return None;
        }
        let mut value: u64 = 0;
        for i in 0..n {
            if self.bits[self.position + i] {
                value |= 1 << (n - 1 - i);
            }
        }
        self.position += n;
        Some(value)
    }

    /// Read n bits as a byte vector and advance position.
    pub fn read_bits_as_bytes(&mut self, n_bits: usize) -> Option<Vec<u8>> {
        if self.position + n_bits > self.bits.len() {
            return None;
        }
        let byte_len = n_bits.div_ceil(8);
        let mut bytes = vec![0u8; byte_len];
        for i in 0..n_bits {
            if self.bits[self.position + i] {
                bytes[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        self.position += n_bits;
        Some(bytes)
    }

    /// Peek at n bits without advancing position.
    pub fn peek_bits(&self, n: usize) -> Option<u64> {
        if self.position + n > self.bits.len() || n > 64 {
            return None;
        }
        let mut value: u64 = 0;
        for i in 0..n {
            if self.bits[self.position + i] {
                value |= 1 << (n - 1 - i);
            }
        }
        Some(value)
    }

    /// Write a single bit (appends to end).
    pub fn write_bit(&mut self, bit: bool) {
        self.bits.push(bit);
    }

    /// Write n bits of a u64 value (MSB first, appends to end).
    pub fn write_bits(&mut self, value: u64, n: usize) {
        for i in (0..n).rev() {
            self.bits.push(((value >> i) & 1) == 1);
        }
    }

    /// Write bytes as bits (appends to end).
    pub fn write_bytes(&mut self, bytes: &[u8], n_bits: usize) {
        let slice = BitSlice::<_, Msb0>::from_slice(bytes);
        let bits_to_write = n_bits.min(slice.len());
        self.bits.extend_from_bitslice(&slice[..bits_to_write]);
    }

    /// Write a full byte slice (all bits).
    pub fn write_all_bytes(&mut self, bytes: &[u8]) {
        self.bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(bytes));
    }

    /// Current read position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set the read position.
    pub fn set_position(&mut self, pos: usize) {
        self.position = pos;
    }

    /// Remaining bits from current position.
    pub fn remaining(&self) -> usize {
        self.bits.len().saturating_sub(self.position)
    }

    /// Total number of bits in the buffer.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Convert to a byte vector (consuming the buffer).
    pub fn into_vec(self) -> Vec<u8> {
        self.bits.into_vec()
    }

    /// Append another BitBuffer's contents.
    pub fn append(&mut self, other: &mut BitBuffer) {
        self.bits.append(&mut other.bits);
    }

    /// Get the underlying BitVec reference (for backward compatibility).
    pub fn as_bitvec(&self) -> &BitVec<u8, Msb0> {
        &self.bits
    }

    /// Get a mutable reference to the underlying BitVec.
    pub fn as_bitvec_mut(&mut self) -> &mut BitVec<u8, Msb0> {
        &mut self.bits
    }

    /// Get a BitSlice view from the current position.
    pub fn as_bitslice_from_position(&self) -> &BitSlice<u8, Msb0> {
        &self.bits[self.position..]
    }
}

impl Default for BitBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let buf = BitBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_from_bytes() {
        let buf = BitBuffer::from_bytes(&[0xAB, 0xCD]);
        assert_eq!(buf.len(), 16);
        assert_eq!(buf.remaining(), 16);
    }

    #[test]
    fn test_write_and_read_bits_roundtrip() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0b1010, 4);
        buf.write_bits(0xABCD, 16);
        buf.write_bits(0b111, 3);

        assert_eq!(buf.len(), 23);

        buf.set_position(0);
        assert_eq!(buf.read_bits(4), Some(0b1010));
        assert_eq!(buf.read_bits(16), Some(0xABCD));
        assert_eq!(buf.read_bits(3), Some(0b111));
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_write_and_read_bit() {
        let mut buf = BitBuffer::new();
        buf.write_bit(true);
        buf.write_bit(false);
        buf.write_bit(true);

        buf.set_position(0);
        assert_eq!(buf.read_bit(), Some(true));
        assert_eq!(buf.read_bit(), Some(false));
        assert_eq!(buf.read_bit(), Some(true));
        assert_eq!(buf.read_bit(), None);
    }

    #[test]
    fn test_peek_does_not_advance() {
        let mut buf = BitBuffer::from_bytes(&[0xF0]);
        assert_eq!(buf.peek_bits(4), Some(0b1111));
        assert_eq!(buf.position(), 0);
        assert_eq!(buf.read_bits(4), Some(0b1111));
        assert_eq!(buf.position(), 4);
        assert_eq!(buf.peek_bits(4), Some(0b0000));
        assert_eq!(buf.position(), 4);
    }

    #[test]
    fn test_read_bits_as_bytes() {
        let mut buf = BitBuffer::from_bytes(&[0xAB, 0xCD, 0xEF]);
        let bytes = buf.read_bits_as_bytes(16).unwrap();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
        assert_eq!(buf.position(), 16);
    }

    #[test]
    fn test_write_bytes() {
        let mut buf = BitBuffer::new();
        buf.write_bytes(&[0xAB, 0xCD], 16);
        assert_eq!(buf.len(), 16);
        let result = buf.into_vec();
        assert_eq!(result, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_write_bytes_partial() {
        let mut buf = BitBuffer::new();
        buf.write_bytes(&[0xFF], 4);
        assert_eq!(buf.len(), 4);
        buf.set_position(0);
        assert_eq!(buf.read_bits(4), Some(0b1111));
    }

    #[test]
    fn test_into_vec() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0xF0, 8);
        assert_eq!(buf.into_vec(), vec![0xF0]);
    }

    #[test]
    fn test_append() {
        let mut buf1 = BitBuffer::new();
        buf1.write_bits(0xAB, 8);

        let mut buf2 = BitBuffer::new();
        buf2.write_bits(0xCD, 8);

        buf1.append(&mut buf2);
        assert_eq!(buf1.len(), 16);
        assert_eq!(buf1.into_vec(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_position_and_remaining() {
        let mut buf = BitBuffer::from_bytes(&[0x00, 0x00]);
        assert_eq!(buf.position(), 0);
        assert_eq!(buf.remaining(), 16);

        buf.read_bits(5);
        assert_eq!(buf.position(), 5);
        assert_eq!(buf.remaining(), 11);

        buf.set_position(10);
        assert_eq!(buf.position(), 10);
        assert_eq!(buf.remaining(), 6);
    }

    #[test]
    fn test_read_beyond_end_returns_none() {
        let mut buf = BitBuffer::from_bytes(&[0xFF]);
        assert_eq!(buf.read_bits(8), Some(0xFF));
        assert_eq!(buf.read_bits(1), None);
        assert_eq!(buf.read_bit(), None);
        assert_eq!(buf.read_bits_as_bytes(1), None);
    }
}
