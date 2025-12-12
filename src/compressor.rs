//! Compression Logic
//!
//! Implements the SCHC Compression/Decompression Actions (CDAs) for
//! converting parsed packet fields into compressed residue bits.

use bitvec::prelude::*;

use crate::field_id::FieldId;
use crate::field_context::FieldContext;
use crate::parser::{FieldValue, StreamingParser};
use crate::rule::{Rule, Field, CompressionAction, ParsedTargetValue};
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
pub fn compress_with_rule(rule: &Rule, parser: &StreamingParser, field_context: &FieldContext) -> CompressionResult {
    let mut bits = BitVec::<u8, Msb0>::new();
    let mut field_details = Vec::new();
    let mut total_original_bits: usize = 0;
    
    // Add Rule ID (this is overhead, counts as sent bits)
    for i in (0..rule.rule_id_length.min(32)).rev() {
        bits.push((rule.rule_id >> i) & 1 == 1);
    }

    // Process each field according to CDA
    for field in &rule.compression {
        if let Some(field_value) = parser.parsed_fields.get(&field.fid) {
            let original_bits = get_field_size_bits(field, field_value, field_context);
            total_original_bits += original_bits as usize;
            
            let bits_before = bits.len();
            compress_field(&mut bits, field, field_value, field_context);
            let sent_bits = (bits.len() - bits_before) as u16;
            
            let savings = original_bits as i16 - sent_bits as i16;
            
            field_details.push(FieldCompressionDetail {
                fid: field.fid,
                original_bits,
                sent_bits,
                savings_bits: savings,
                cda: field.cda,
            });
        }
    }

    let compressed_bits = bits.len();
    let data = bits.into_vec();
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
fn compress_field(bits: &mut BitVec<u8, Msb0>, field: &Field, value: &FieldValue, field_context: &FieldContext) {
    match field.cda {
        CompressionAction::NotSent => {
            // Nothing sent
        }
        CompressionAction::ValueSent => {
            send_field_value(bits, field, value);
        }
        CompressionAction::MappingSent => {
            if let Some(ref tv) = field.tv {
                if let serde_json::Value::Array(arr) = tv {
                    let num_items = arr.len();
                    let bits_needed = if num_items <= 1 {
                        0
                    } else {
                        (usize::BITS - (num_items - 1).leading_zeros()) as u8
                    };
                    
                    // Find matching index and send it
                    if let Some(ParsedTargetValue::Mapping(tv_list)) = &field.parsed_tv {
                        for (index, tv) in tv_list.iter().enumerate() {
                            if values_match(value, tv) {
                                for i in (0..bits_needed).rev() {
                                    bits.push(((index as u64) >> i) & 1 == 1);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        CompressionAction::Lsb(_) => {
            let msb_bits = field.mo_val.unwrap_or(0);
            let field_size = get_field_size_bits(field, value, field_context);
            
            if msb_bits as u16 <= field_size {
                let lsb_bits = field_size - msb_bits as u16;
                send_lsb(bits, value, lsb_bits as u8);
            }
        }
        CompressionAction::Compute => {
            // Computed at decompression - nothing sent
        }
    }
}

/// Send the full field value
fn send_field_value(bits: &mut BitVec<u8, Msb0>, field: &Field, value: &FieldValue) {
    // Determine actual field size: FL from rule -> FieldId default -> Rust type size
    let field_bits: Option<u16> = field.get_field_length()
        .or_else(|| field.fid.default_size_bits());
    
    if let Some(n_bits) = field_bits {
        match value {
            FieldValue::U8(v) => send_n_bits(bits, *v as u64, n_bits),
            FieldValue::U16(v) => send_n_bits(bits, *v as u64, n_bits),
            FieldValue::U32(v) => send_n_bits(bits, *v as u64, n_bits),
            FieldValue::U64(v) => send_n_bits(bits, *v, n_bits),
            FieldValue::Bytes(v) => {
                let byte_len = ((n_bits + 7) / 8) as usize;
                let bytes_to_send = &v[..byte_len.min(v.len())];
                bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(bytes_to_send));
            },
            FieldValue::Ipv4(v) => {
                let byte_len = ((n_bits + 7) / 8) as usize;
                let bytes = v.octets();
                bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&bytes[..byte_len.min(4)]));
            },
            FieldValue::Ipv6(v) => {
                let byte_len = ((n_bits + 7) / 8) as usize;
                let bytes = v.octets();
                bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&bytes[..byte_len.min(16)]));
            },
        }
    } else {
        // Fallback to full Rust type size (should rarely happen)
        match value {
            FieldValue::U8(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.to_be_bytes())),
            FieldValue::U16(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.to_be_bytes())),
            FieldValue::U32(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.to_be_bytes())),
            FieldValue::U64(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.to_be_bytes())),
            FieldValue::Bytes(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(v)),
            FieldValue::Ipv4(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.octets())),
            FieldValue::Ipv6(v) => bits.extend_from_bitslice(BitSlice::<_, Msb0>::from_slice(&v.octets())),
        }
    }
}

/// Send n bits of a value (MSB first)
#[inline]
fn send_n_bits(bits: &mut BitVec<u8, Msb0>, value: u64, n_bits: u16) {
    for i in (0..n_bits).rev() {
        bits.push(((value >> i) & 1) == 1);
    }
}

/// Send the LSB portion of a value
#[inline]
fn send_lsb(bits: &mut BitVec<u8, Msb0>, value: &FieldValue, num_bits: u8) {
    let value_u64 = match value {
        FieldValue::U8(v) => *v as u64,
        FieldValue::U16(v) => *v as u64,
        FieldValue::U32(v) => *v as u64,
        FieldValue::U64(v) => *v,
        _ => return,
    };

    for i in (0..num_bits).rev() {
        bits.push(((value_u64 >> i) & 1) == 1);
    }
}

/// Get the field size in bits
pub fn get_field_size_bits(field: &Field, value: &FieldValue, field_context: &FieldContext) -> u16 {
    if let Some(fl) = field.get_field_length() {
        return fl;
    }
    
    if let Some(bits) = field_context.get_field_length_bits(field.fid.as_str()) {
        return bits;
    }
    
    if let Some(bits) = field.fid.default_size_bits() {
        return bits;
    }
    
    value.size_bits()
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
        // Case where compression makes it worse
        let packet = CompressedPacket {
            data: vec![0x0F; 10],
            bit_length: 80,
            rule_id: 1,
            rule_id_length: 8,
            original_header_bits: 32,   // 4 bytes original
            compressed_header_bits: 80, // 10 bytes compressed (worse!)
            original_header_data: Vec::new(),
        };
        
        assert_eq!(packet.savings_bits(), -48);
        assert_eq!(packet.savings_bytes(), -6.0);
    }

    // =========================================================================
    // send_n_bits tests
    // =========================================================================

    #[test]
    fn test_send_n_bits_4_bits() {
        let mut bits = BitVec::<u8, Msb0>::new();
        send_n_bits(&mut bits, 0b1010, 4);
        
        assert_eq!(bits.len(), 4);
        assert_eq!(bits[0], true);   // 1
        assert_eq!(bits[1], false);  // 0
        assert_eq!(bits[2], true);   // 1
        assert_eq!(bits[3], false);  // 0
    }

    #[test]
    fn test_send_n_bits_16_bits() {
        let mut bits = BitVec::<u8, Msb0>::new();
        send_n_bits(&mut bits, 0xABCD, 16);
        
        assert_eq!(bits.len(), 16);
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_send_n_bits_zero() {
        let mut bits = BitVec::<u8, Msb0>::new();
        send_n_bits(&mut bits, 0, 8);
        
        assert_eq!(bits.len(), 8);
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn test_send_n_bits_partial_byte() {
        let mut bits = BitVec::<u8, Msb0>::new();
        send_n_bits(&mut bits, 0b11111, 5);
        
        assert_eq!(bits.len(), 5);
        for i in 0..5 {
            assert_eq!(bits[i], true);
        }
    }

    // =========================================================================
    // send_lsb tests
    // =========================================================================

    #[test]
    fn test_send_lsb_u8() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let value = FieldValue::U8(0b11110011); // 0xF3
        send_lsb(&mut bits, &value, 4); // Send LSB 4 bits: 0011
        
        assert_eq!(bits.len(), 4);
        assert_eq!(bits[0], false);  // 0
        assert_eq!(bits[1], false);  // 0
        assert_eq!(bits[2], true);   // 1
        assert_eq!(bits[3], true);   // 1
    }

    #[test]
    fn test_send_lsb_u16() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let value = FieldValue::U16(0x1234);
        send_lsb(&mut bits, &value, 8); // Send LSB 8 bits: 0x34
        
        assert_eq!(bits.len(), 8);
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0x34]);
    }

    #[test]
    fn test_send_lsb_bytes_returns_early() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let value = FieldValue::Bytes(vec![0x12, 0x34]);
        send_lsb(&mut bits, &value, 8);
        
        // Bytes should return early without adding anything
        assert_eq!(bits.len(), 0);
    }

    // =========================================================================
    // get_field_size_bits tests
    // =========================================================================

    #[test]
    fn test_get_field_size_from_fl() {
        // When FL is specified in the field, use it
        let field = Field {
            fid: FieldId::Ipv6Ver,
            fl: Some(4),
            tv: None,
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: None,
        };
        let value = FieldValue::U8(6);
        let context = FieldContext::default();
        
        assert_eq!(get_field_size_bits(&field, &value, &context), 4);
    }

    #[test]
    fn test_get_field_size_from_field_id_default() {
        // When FL is not specified, use FieldId default
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::ValueSent,
            mo_val: None,
            parsed_tv: None,
        };
        let value = FieldValue::U16(8080);
        let context = FieldContext::default();
        
        assert_eq!(get_field_size_bits(&field, &value, &context), 16); // UDP port is 16 bits
    }

    #[test]
    fn test_get_field_size_from_value() {
        // When nothing else is available, use value's size
        let field = Field {
            fid: FieldId::Ipv6Ver, // 4-bit default
            fl: None,
            tv: None,
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: None,
        };
        // FieldId::Ipv6Ver has a default of 4 bits, so it should use that
        // not the value's size (8 bits for U8)
        let value = FieldValue::U8(6);
        let context = FieldContext::default();
        
        assert_eq!(get_field_size_bits(&field, &value, &context), 4);
    }

    // =========================================================================
    // Bit pattern verification tests
    // =========================================================================

    #[test]
    fn test_rule_id_encoding() {
        // Verify rule ID is encoded correctly in MSB order
        let mut bits = BitVec::<u8, Msb0>::new();
        let rule_id: u32 = 0b11110000; // 240
        let rule_id_length: u8 = 8;
        
        for i in (0..rule_id_length.min(32)).rev() {
            bits.push((rule_id >> i) & 1 == 1);
        }
        
        assert_eq!(bits.len(), 8);
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0xF0]);
    }

    #[test]
    fn test_rule_id_4_bits() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let rule_id: u32 = 0b1010; // 10
        let rule_id_length: u8 = 4;
        
        for i in (0..rule_id_length.min(32)).rev() {
            bits.push((rule_id >> i) & 1 == 1);
        }
        
        assert_eq!(bits.len(), 4);
        assert_eq!(bits[0], true);   // 1
        assert_eq!(bits[1], false);  // 0
        assert_eq!(bits[2], true);   // 1
        assert_eq!(bits[3], false);  // 0
    }

    // =========================================================================
    // CDA behavior tests
    // =========================================================================

    #[test]
    fn test_cda_not_sent_adds_nothing() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let field = Field {
            fid: FieldId::Ipv6Ver,
            fl: Some(4),
            tv: Some(serde_json::json!(6)),
            mo: crate::rule::MatchingOperator::Equal,
            cda: CompressionAction::NotSent,
            mo_val: None,
            parsed_tv: Some(crate::rule::ParsedTargetValue::Single(crate::rule::RuleValue::U64(6))),
        };
        let value = FieldValue::U8(6);
        let context = FieldContext::default();
        
        compress_field(&mut bits, &field, &value, &context);
        
        assert_eq!(bits.len(), 0); // Nothing should be added
    }

    #[test]
    fn test_cda_compute_adds_nothing() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let field = Field {
            fid: FieldId::UdpCksum,
            fl: Some(16),
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::Compute,
            mo_val: None,
            parsed_tv: None,
        };
        let value = FieldValue::U16(0x1234);
        let context = FieldContext::default();
        
        compress_field(&mut bits, &field, &value, &context);
        
        assert_eq!(bits.len(), 0); // Nothing should be added
    }

    #[test]
    fn test_cda_value_sent_adds_full_value() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: Some(16),
            tv: None,
            mo: crate::rule::MatchingOperator::Ignore,
            cda: CompressionAction::ValueSent,
            mo_val: None,
            parsed_tv: None,
        };
        let value = FieldValue::U16(0xABCD);
        let context = FieldContext::default();
        
        compress_field(&mut bits, &field, &value, &context);
        
        assert_eq!(bits.len(), 16);
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_cda_lsb() {
        let mut bits = BitVec::<u8, Msb0>::new();
        let field = Field {
            fid: FieldId::UdpSrcPort,
            fl: Some(16),
            tv: Some(serde_json::json!(0x1200)), // MSB 8 bits: 0x12
            mo: crate::rule::MatchingOperator::Msb(8),
            cda: CompressionAction::Lsb(8),
            mo_val: Some(8), // MSB matched on 8 bits
            parsed_tv: Some(crate::rule::ParsedTargetValue::Single(crate::rule::RuleValue::U64(0x1200))),
        };
        let value = FieldValue::U16(0x1234); // LSB 8 bits: 0x34
        let context = FieldContext::default();
        
        compress_field(&mut bits, &field, &value, &context);
        
        assert_eq!(bits.len(), 8); // Only LSB 8 bits sent
        let bytes = bits.into_vec();
        assert_eq!(bytes, vec![0x34]);
    }
}
