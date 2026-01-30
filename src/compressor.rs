//! Compression Logic
//!
//! Implements the SCHC Compression/Decompression Actions (CDAs) for
//! converting parsed packet fields into compressed residue bits.

use crate::bit_buffer::BitBuffer;
use crate::field_id::FieldId;
use crate::parser::{FieldValue, StreamingParser};
use crate::rule::{Rule, Field, FieldLength, CompressionAction, ParsedTargetValue};
use crate::matcher::values_match;

// =============================================================================
// Compression Result Types
// =============================================================================

/// Result of compressing a packet with a matched rule
pub struct CompressionResult {
    pub rule_id: u32,
    pub rule_id_length: u8,
    pub data: Vec<u8>,
    pub compressed_bits: usize,
    pub original_bits: usize,
    pub savings_bits: i64,
    pub field_count: usize,
    pub field_details: Vec<FieldCompressionDetail>,
}

/// Per-field compression details for debugging
#[derive(Debug, Clone)]
pub struct FieldCompressionDetail {
    pub fid: FieldId,
    pub original_bits: u16,
    pub sent_bits: u16,
    pub savings_bits: i16,
    pub cda: CompressionAction,
}

// =============================================================================
// Compressed Packet
// =============================================================================

/// Final compressed packet output
#[derive(Debug, Clone)]
pub struct CompressedPacket {
    pub data: Vec<u8>,
    pub bit_length: usize,
    pub rule_id: u32,
    pub rule_id_length: u8,
    pub original_header_bits: usize,
    pub compressed_header_bits: usize,
    /// Original header bytes (for debugging)
    pub original_header_data: Vec<u8>,
}

impl CompressedPacket {
    /// Savings in bits
    pub fn savings_bits(&self) -> i64 {
        self.original_header_bits as i64 - self.compressed_header_bits as i64
    }
    
    /// Savings displayed as bytes (with fractional precision)
    pub fn savings_bytes(&self) -> f64 {
        self.savings_bits() as f64 / 8.0
    }
}

// =============================================================================
// Compression Functions
// =============================================================================

/// Compress a packet using a matched rule
pub fn compress_with_rule(rule: &Rule, parser: &StreamingParser) -> CompressionResult {
    let mut buf = BitBuffer::new();
    let mut field_details = Vec::new();
    let mut total_original_bits: usize = 0;

    // Add Rule ID (this is overhead, counts as sent bits)
    buf.write_bits(rule.rule_id as u64, rule.rule_id_length.min(32) as usize);

    // Store field values for context propagation (dynamic field lengths)
    let mut field_values: Vec<Option<&FieldValue>> = Vec::with_capacity(rule.compression.len());

    // Process each field according to CDA
    for field in rule.compression.iter() {
        if let Some(field_value) = parser.parsed_fields.get(&field.fid) {
            let original_bits = get_field_size_bits_with_context(
                field, field_value, &field_values, &rule.compression,
            );
            total_original_bits += original_bits as usize;

            let bits_before = buf.len();
            compress_field(&mut buf, field, field_value);
            let sent_bits = (buf.len() - bits_before) as u16;

            let savings = original_bits as i16 - sent_bits as i16;

            field_details.push(FieldCompressionDetail {
                fid: field.fid,
                original_bits,
                sent_bits,
                savings_bits: savings,
                cda: field.cda,
            });

            field_values.push(Some(field_value));
        } else {
            field_values.push(None);
        }
    }

    let compressed_bits = buf.len();
    let data = buf.into_vec();
    let field_count = rule.compression.len();

    // Savings = original field bits - (rule_id + residue bits)
    let savings_bits = total_original_bits as i64 - compressed_bits as i64;

    CompressionResult {
        rule_id: rule.rule_id,
        rule_id_length: rule.rule_id_length,
        data,
        compressed_bits,
        original_bits: total_original_bits,
        savings_bits,
        field_count,
        field_details,
    }
}

/// Compress a single field according to its CDA
fn compress_field(buf: &mut BitBuffer, field: &Field, value: &FieldValue) {
    match field.cda {
        CompressionAction::NotSent => {
            // Nothing sent
        }
        CompressionAction::ValueSent => {
            send_field_value(buf, field, value);
        }
        CompressionAction::MappingSent => {
            if let Some(ref tv) = field.tv
                && let serde_json::Value::Array(arr) = tv {
                    let num_items = arr.len();
                    let bits_needed = if num_items <= 1 {
                        0
                    } else {
                        (usize::BITS - (num_items - 1).leading_zeros()) as usize
                    };

                    // Find matching index and send it
                    if let Some(ParsedTargetValue::Mapping(tv_list)) = &field.parsed_tv {
                        for (index, tv) in tv_list.iter().enumerate() {
                            if values_match(value, tv) {
                                buf.write_bits(index as u64, bits_needed);
                                break;
                            }
                        }
                    }
                }
        }
        CompressionAction::Lsb => {
            let msb_bits = field.mo_val.unwrap_or(0);
            let field_size = get_field_size_bits(field, value);

            if msb_bits as u16 <= field_size {
                let lsb_bits = field_size - msb_bits as u16;
                send_lsb(buf, value, lsb_bits as u8);
            }
        }
        CompressionAction::Compute => {
            // Computed at decompression - nothing sent
        }
    }
}

/// Send the full field value
fn send_field_value(buf: &mut BitBuffer, field: &Field, value: &FieldValue) {
    // Determine actual field size: FL from rule -> FieldId default -> Rust type size
    let field_bits: Option<u16> = field.get_field_length()
        .or_else(|| field.fid.default_size_bits());

    if let Some(n_bits) = field_bits {
        match value {
            FieldValue::U8(v) => buf.write_bits(*v as u64, n_bits as usize),
            FieldValue::U16(v) => buf.write_bits(*v as u64, n_bits as usize),
            FieldValue::U32(v) => buf.write_bits(*v as u64, n_bits as usize),
            FieldValue::U64(v) => buf.write_bits(*v, n_bits as usize),
            FieldValue::Bytes(v) => {
                let byte_len = n_bits.div_ceil(8) as usize;
                let bytes_to_send = &v[..byte_len.min(v.len())];
                buf.write_bytes(bytes_to_send, n_bits as usize);
            },
            FieldValue::Ipv4(v) => {
                let byte_len = n_bits.div_ceil(8) as usize;
                let bytes = v.octets();
                buf.write_bytes(&bytes[..byte_len.min(4)], n_bits as usize);
            },
            FieldValue::Ipv6(v) => {
                let byte_len = n_bits.div_ceil(8) as usize;
                let bytes = v.octets();
                buf.write_bytes(&bytes[..byte_len.min(16)], n_bits as usize);
            },
            FieldValue::ComputePlaceholder => {}
        }
    } else {
        // Fallback to full Rust type size (should rarely happen)
        match value {
            FieldValue::U8(v) => buf.write_all_bytes(&v.to_be_bytes()),
            FieldValue::U16(v) => buf.write_all_bytes(&v.to_be_bytes()),
            FieldValue::U32(v) => buf.write_all_bytes(&v.to_be_bytes()),
            FieldValue::U64(v) => buf.write_all_bytes(&v.to_be_bytes()),
            FieldValue::Bytes(v) => buf.write_all_bytes(v),
            FieldValue::Ipv4(v) => buf.write_all_bytes(&v.octets()),
            FieldValue::Ipv6(v) => buf.write_all_bytes(&v.octets()),
            FieldValue::ComputePlaceholder => {}
        }
    }
}

/// Send the LSB portion of a value
#[inline]
fn send_lsb(buf: &mut BitBuffer, value: &FieldValue, num_bits: u8) {
    let value_u64 = match value {
        FieldValue::U8(v) => *v as u64,
        FieldValue::U16(v) => *v as u64,
        FieldValue::U32(v) => *v as u64,
        FieldValue::U64(v) => *v,
        _ => return,
    };

    buf.write_bits(value_u64, num_bits as usize);
}

/// Get the field size in bits
pub fn get_field_size_bits(field: &Field, value: &FieldValue) -> u16 {
    // Priority: 1. Explicit FL in rule, 2. FieldId default from JSON, 3. Value size
    if let Some(fl) = field.get_field_length() {
        return fl;
    }

    if let Some(bits) = field.fid.default_size_bits() {
        return bits;
    }

    value.size_bits()
}

/// Get field size in bits using context from previously compressed fields
/// This resolves fl_func (FieldLength) using the rule's entry list
pub fn get_field_size_bits_with_context(
    field: &Field,
    value: &FieldValue,
    field_values: &[Option<&FieldValue>],
    rule_entries: &[Field],
) -> u16 {
    // Priority: 1. fl_func with context resolution
    if let Some(ref fl_func) = field.fl_func {
        if let Some(bits) = resolve_compressor_field_length(fl_func, field_values, rule_entries) {
            return bits;
        }
    }
    // Fall through to static resolution
    get_field_size_bits(field, value)
}

/// Resolve a FieldLength function using compressor context
fn resolve_compressor_field_length(
    fl_func: &FieldLength,
    field_values: &[Option<&FieldValue>],
    _rule_entries: &[Field],
) -> Option<u16> {
    match fl_func {
        FieldLength::Fixed(bits) => Some(*bits),
        FieldLength::TokenLength => {
            // Find TKL field value in the already-compressed fields
            for fv in field_values.iter().flatten() {
                // TKL is always a small integer
                if let FieldValue::U8(v) = fv {
                    // Heuristic: TKL is 0-8, so any U8 in that range could be TKL.
                    // In practice, TokenLength is set on the Token field which always
                    // follows TKL in the compression list.
                    if *v <= 8 {
                        return Some((*v as u16) * 8);
                    }
                }
            }
            None
        }
        FieldLength::LengthBytes(entry_idx) => {
            let ref_value = field_values.get(*entry_idx)?.as_ref()?;
            let len = field_value_as_u16(ref_value)?;
            Some(len * 8)
        }
        FieldLength::LengthBits(entry_idx) => {
            let ref_value = field_values.get(*entry_idx)?.as_ref()?;
            field_value_as_u16(ref_value)
        }
        FieldLength::Variable => None,
    }
}

/// Extract a u16 value from a FieldValue
fn field_value_as_u16(value: &FieldValue) -> Option<u16> {
    match value {
        FieldValue::U8(v) => Some(*v as u16),
        FieldValue::U16(v) => Some(*v),
        FieldValue::U32(v) => Some(*v as u16),
        FieldValue::U64(v) => Some(*v as u16),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // CompressedPacket tests
    // =========================================================================

    #[test]
    fn test_compressed_packet_savings_bits() {
        let packet = CompressedPacket {
            data: vec![0x0F],
            bit_length: 8,
            rule_id: 1,
            rule_id_length: 8,
            original_header_bits: 160,  // 20 bytes
            compressed_header_bits: 8,  // 1 byte
            original_header_data: Vec::new(),
        };

        assert_eq!(packet.savings_bits(), 152);
    }

    #[test]
    fn test_compressed_packet_savings_bytes() {
        let packet = CompressedPacket {
            data: vec![0x0F],
            bit_length: 8,
            rule_id: 1,
            rule_id_length: 8,
            original_header_bits: 160,
            compressed_header_bits: 8,
            original_header_data: Vec::new(),
        };

        assert_eq!(packet.savings_bytes(), 19.0);
    }

    #[test]
    fn test_compressed_packet_negative_savings() {
        let packet = CompressedPacket {
            data: vec![0x0F; 10],
            bit_length: 80,
            rule_id: 1,
            rule_id_length: 8,
            original_header_bits: 32,
            compressed_header_bits: 80,
            original_header_data: Vec::new(),
        };

        assert_eq!(packet.savings_bits(), -48);
        assert_eq!(packet.savings_bytes(), -6.0);
    }

    // =========================================================================
    // BitBuffer write_bits tests
    // =========================================================================

    #[test]
    fn test_write_bits_4_bits() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0b1010, 4);

        assert_eq!(buf.len(), 4);
        buf.set_position(0);
        assert_eq!(buf.read_bits(4), Some(0b1010));
    }

    #[test]
    fn test_write_bits_16_bits() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0xABCD, 16);

        assert_eq!(buf.len(), 16);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_write_bits_zero() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0, 8);

        assert_eq!(buf.len(), 8);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn test_write_bits_partial_byte() {
        let mut buf = BitBuffer::new();
        buf.write_bits(0b11111, 5);

        assert_eq!(buf.len(), 5);
        buf.set_position(0);
        assert_eq!(buf.read_bits(5), Some(0b11111));
    }

    // =========================================================================
    // send_lsb tests
    // =========================================================================

    #[test]
    fn test_send_lsb_u8() {
        let mut buf = BitBuffer::new();
        let value = FieldValue::U8(0b11110011); // 0xF3
        send_lsb(&mut buf, &value, 4); // Send LSB 4 bits: 0011

        assert_eq!(buf.len(), 4);
        buf.set_position(0);
        assert_eq!(buf.read_bits(4), Some(0b0011));
    }

    #[test]
    fn test_send_lsb_u16() {
        let mut buf = BitBuffer::new();
        let value = FieldValue::U16(0x1234);
        send_lsb(&mut buf, &value, 8); // Send LSB 8 bits: 0x34

        assert_eq!(buf.len(), 8);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0x34]);
    }

    #[test]
    fn test_send_lsb_bytes_returns_early() {
        let mut buf = BitBuffer::new();
        let value = FieldValue::Bytes(vec![0x12, 0x34]);
        send_lsb(&mut buf, &value, 8);

        assert_eq!(buf.len(), 0);
    }

    // =========================================================================
    // get_field_size_bits tests
    // =========================================================================

    #[test]
    fn test_get_field_size_from_fl() {
        let field = Field {
            fid: FieldId::Ipv6Ver,
            fl: Some(4),
            di: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        };
        let value = FieldValue::U8(6);

        assert_eq!(get_field_size_bits(&field, &value), 4);
    }

    #[test]
    fn test_get_field_size_from_field_id_default() {
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: None,
            di: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::ValueSent,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        };
        let value = FieldValue::U16(8080);

        assert_eq!(get_field_size_bits(&field, &value), 16);
    }

    #[test]
    fn test_get_field_size_from_value() {
        let field = Field {
            fid: FieldId::Ipv6Ver,
            fl: None,
            di: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        };
        let value = FieldValue::U8(6);

        assert_eq!(get_field_size_bits(&field, &value), 4);
    }

    // =========================================================================
    // Bit pattern verification tests
    // =========================================================================

    #[test]
    fn test_rule_id_encoding() {
        let mut buf = BitBuffer::new();
        let rule_id: u32 = 0b11110000; // 240
        let rule_id_length: u8 = 8;

        buf.write_bits(rule_id as u64, rule_id_length as usize);

        assert_eq!(buf.len(), 8);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0xF0]);
    }

    #[test]
    fn test_rule_id_4_bits() {
        let mut buf = BitBuffer::new();
        let rule_id: u32 = 0b1010; // 10
        let rule_id_length: u8 = 4;

        buf.write_bits(rule_id as u64, rule_id_length as usize);

        assert_eq!(buf.len(), 4);
        buf.set_position(0);
        assert_eq!(buf.read_bits(4), Some(0b1010));
    }

    // =========================================================================
    // CDA behavior tests
    // =========================================================================

    #[test]
    fn test_cda_not_sent_adds_nothing() {
        let mut buf = BitBuffer::new();
        let field = Field {
            fid: FieldId::Ipv6Ver,
            fl: Some(4),
            di: None,
            tv: Some(serde_json::json!(6)),
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: Some(crate::rule::ParsedTargetValue::Single(crate::rule::RuleValue::U64(6))),
            fl_func: None,
        };
        let value = FieldValue::U8(6);

        compress_field(&mut buf, &field, &value);

        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_cda_compute_adds_nothing() {
        let mut buf = BitBuffer::new();
        let field = Field {
            fid: FieldId::UdpCksum,
            fl: Some(16),
            di: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::Compute,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        };
        let value = FieldValue::U16(0x1234);

        compress_field(&mut buf, &field, &value);

        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_cda_value_sent_adds_full_value() {
        let mut buf = BitBuffer::new();
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: Some(16),
            di: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::ValueSent,
            mo_val: None,
            parsed_tv: None,
            fl_func: None,
        };
        let value = FieldValue::U16(0xABCD);

        compress_field(&mut buf, &field, &value);

        assert_eq!(buf.len(), 16);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_cda_lsb() {
        let mut buf = BitBuffer::new();
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: Some(16),
            di: None,
            tv: Some(serde_json::json!(0x1200)),
            mo: crate::rule::MatchingOperator::Msb(8),
            cda: CompressionAction::Lsb,
            mo_val: Some(8),
            parsed_tv: Some(crate::rule::ParsedTargetValue::Single(crate::rule::RuleValue::U64(0x1200))),
            fl_func: None,
        };
        let value = FieldValue::U16(0x1234);

        compress_field(&mut buf, &field, &value);

        assert_eq!(buf.len(), 8);
        let bytes = buf.into_vec();
        assert_eq!(bytes, vec![0x34]);
    }
}
