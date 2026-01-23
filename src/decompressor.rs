//! Decompression Logic
//!
//! Implements the SCHC Decompression Actions for converting compressed
//! SCHC packets back into original packet headers.

use bitvec::prelude::*;
use std::collections::HashMap;

use crate::error::{Result, SchcError};
use crate::field_id::FieldId;
use crate::parser::{FieldValue, Direction};
use crate::rule::{Rule, Field, CompressionAction, ParsedTargetValue, RuleValue};

// =============================================================================
// Decompression Result Types
// =============================================================================

/// Result of decompressing a SCHC packet
#[derive(Debug, Clone)]
pub struct DecompressedPacket {
    /// Reconstructed header bytes
    pub header_data: Vec<u8>,
    /// Full packet (header + payload)
    pub full_data: Vec<u8>,
    /// Rule ID used for decompression
    pub rule_id: u32,
    /// Rule ID length in bits
    pub rule_id_length: u8,
    /// Total bits consumed from compressed data
    pub bits_consumed: usize,
    /// Number of fields reconstructed
    pub field_count: usize,
    /// Reconstructed field values (for verification)
    pub fields: HashMap<FieldId, FieldValue>,
}

// =============================================================================
// Rule ID Matching
// =============================================================================

/// Match a rule ID from compressed data using variable-length matching
/// 
/// Rules are checked in order of decreasing rule_id_length (most specific first).
/// This allows for variable-length rule ID encoding as per RFC 8724.
pub fn match_rule_id<'a>(data: &[u8], rules: &'a [Rule]) -> Result<&'a Rule> {
    if data.is_empty() {
        return Err(SchcError::Decompression("Empty compressed data".to_string()));
    }
    
    let bits = BitSlice::<_, Msb0>::from_slice(data);
    
    // Sort rules by rule_id_length descending for proper variable-length matching
    let mut sorted_rules: Vec<&Rule> = rules.iter().collect();
    sorted_rules.sort_by(|a, b| b.rule_id_length.cmp(&a.rule_id_length));
    
    for rule in sorted_rules {
        let id_len = rule.rule_id_length as usize;
        if bits.len() < id_len {
            continue;
        }
        
        // Extract rule_id_length bits from the beginning
        let mut extracted_id: u32 = 0;
        for i in 0..id_len {
            if bits[i] {
                extracted_id |= 1 << (id_len - 1 - i);
            }
        }
        
        if extracted_id == rule.rule_id {
            return Ok(rule);
        }
    }
    
    Err(SchcError::Decompression("No matching rule ID found".to_string()))
}

// =============================================================================
// Main Decompression Entry Point
// =============================================================================

/// Decompress a SCHC packet using the provided rules
///
/// # Arguments
/// * `compressed_data` - The compressed SCHC packet (rule ID + residues)
/// * `rules` - Available SCHC compression rules
/// * `direction` - Packet direction (for directional field reconstruction)
/// * `original_payload` - Optional payload to append to reconstructed header
///
/// # Returns
/// * `DecompressedPacket` with reconstructed header and fields
pub fn decompress_packet(
    compressed_data: &[u8],
    rules: &[Rule],
    direction: Direction,
    original_payload: Option<&[u8]>,
) -> Result<DecompressedPacket> {
    // Match rule ID
    let rule = match_rule_id(compressed_data, rules)?;
    
    let bits = BitSlice::<_, Msb0>::from_slice(compressed_data);
    let mut bit_pos = rule.rule_id_length as usize;
    
    // Decompress each field according to its CDA
    // Pass already-decompressed fields for QUIC CID length lookup
    let mut fields: HashMap<FieldId, FieldValue> = HashMap::new();
    
    for field in &rule.compression {
        let value = decompress_field(bits, &mut bit_pos, field, &fields)?;
        fields.insert(field.fid, value);
    }
    
    // Build the reconstructed header
    let header_data = build_header(&fields, direction, original_payload)?;
    
    // Build full packet (header + payload)
    let mut full_data = header_data.clone();
    if let Some(payload) = original_payload {
        full_data.extend_from_slice(payload);
    }
    
    Ok(DecompressedPacket {
        header_data,
        full_data,
        rule_id: rule.rule_id,
        rule_id_length: rule.rule_id_length,
        bits_consumed: bit_pos,
        field_count: rule.compression.len(),
        fields,
    })
}

// =============================================================================
// Field Decompression
// =============================================================================

/// Decompress a single field based on its CDA
fn decompress_field(
    bits: &BitSlice<u8, Msb0>,
    bit_pos: &mut usize,
    field: &Field,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
) -> Result<FieldValue> {
    match field.cda {
        CompressionAction::NotSent => {
            // Restore from Target Value
            restore_from_tv(field)
        }
        CompressionAction::ValueSent => {
            // Read full field value from residue
            // For QUIC CID fields, get length from previously decompressed length field
            let field_bits = get_field_size_bits_with_context(field, decompressed_fields);
            read_field_value(bits, bit_pos, field_bits, field.fid)
        }
        CompressionAction::MappingSent => {
            // Read index and lookup in TV array
            decompress_mapping(bits, bit_pos, field)
        }
        CompressionAction::Lsb => {
            // Combine MSB from TV with LSB from residue
            decompress_lsb(bits, bit_pos, field)
        }
        CompressionAction::Compute => {
            // Placeholder - will be computed during header reconstruction
            Ok(FieldValue::ComputePlaceholder)
        }
    }
}

/// Restore field value from Target Value (for not-sent CDA)
fn restore_from_tv(field: &Field) -> Result<FieldValue> {
    match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => rule_value_to_field_value(rv, field.fid),
        Some(ParsedTargetValue::Mapping(_)) => {
            Err(SchcError::Decompression(format!(
                "Field {} has not-sent CDA but mapping TV", field.fid
            )))
        }
        None => {
            Err(SchcError::Decompression(format!(
                "Field {} has not-sent CDA but no TV", field.fid
            )))
        }
    }
}

/// Decompress mapping-sent field (read index, lookup TV)
fn decompress_mapping(
    bits: &BitSlice<u8, Msb0>,
    bit_pos: &mut usize,
    field: &Field,
) -> Result<FieldValue> {
    if let Some(ParsedTargetValue::Mapping(tv_list)) = &field.parsed_tv {
        let num_items = tv_list.len();
        if num_items == 0 {
            return Err(SchcError::Decompression(format!(
                "Field {} has empty mapping", field.fid
            )));
        }
        
        // Calculate bits needed for index
        let index_bits = if num_items <= 1 {
            0
        } else {
            (usize::BITS - (num_items - 1).leading_zeros()) as usize
        };
        
        // Read index
        let index = if index_bits > 0 {
            read_bits_as_u64(bits, bit_pos, index_bits)? as usize
        } else {
            0
        };
        
        if index >= tv_list.len() {
            return Err(SchcError::Decompression(format!(
                "Field {} mapping index {} out of bounds (max: {})",
                field.fid, index, tv_list.len() - 1
            )));
        }
        
        rule_value_to_field_value(&tv_list[index], field.fid)
    } else {
        Err(SchcError::Decompression(format!(
            "Field {} has mapping-sent CDA but no mapping TV", field.fid
        )))
    }
}

/// Decompress LSB field (combine MSB from TV + LSB from residue)
fn decompress_lsb(
    bits: &BitSlice<u8, Msb0>,
    bit_pos: &mut usize,
    field: &Field,
) -> Result<FieldValue> {
    let msb_bits = field.mo_val.unwrap_or(0) as usize;
    let field_size = get_field_size_bits(field) as usize;
    
    if msb_bits > field_size {
        return Err(SchcError::Decompression(format!(
            "Field {} MSB bits ({}) exceeds field size ({})",
            field.fid, msb_bits, field_size
        )));
    }
    
    let lsb_bits = field_size - msb_bits;
    
    // Get MSB portion from TV
    let msb_value = match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => {
            match rv {
                RuleValue::U64(v) => *v,
                _ => return Err(SchcError::Decompression(format!(
                    "Field {} has non-numeric TV for LSB", field.fid
                ))),
            }
        }
        _ => return Err(SchcError::Decompression(format!(
            "Field {} has LSB CDA but no TV", field.fid
        ))),
    };
    
    // Read LSB portion from residue
    let lsb_value = read_bits_as_u64(bits, bit_pos, lsb_bits)?;
    
    // Combine: MSB stays in upper bits, LSB fills lower bits
    // The TV should have the MSB portion already shifted to the correct position
    let msb_mask = ((1u64 << msb_bits) - 1) << lsb_bits;
    let combined = (msb_value & msb_mask) | lsb_value;
    
    // Return appropriate FieldValue type based on field size
    Ok(match field_size {
        1..=8 => FieldValue::U8(combined as u8),
        9..=16 => FieldValue::U16(combined as u16),
        17..=32 => FieldValue::U32(combined as u32),
        _ => FieldValue::U64(combined),
    })
}

// =============================================================================
// Bit Reading Helpers
// =============================================================================

/// Read n bits from the BitSlice and return as u64
fn read_bits_as_u64(
    bits: &BitSlice<u8, Msb0>,
    bit_pos: &mut usize,
    n_bits: usize,
) -> Result<u64> {
    if *bit_pos + n_bits > bits.len() {
        return Err(SchcError::Decompression(format!(
            "Not enough bits: need {} at position {}, have {}",
            n_bits, *bit_pos, bits.len()
        )));
    }
    
    let mut value: u64 = 0;
    for i in 0..n_bits {
        if bits[*bit_pos + i] {
            value |= 1 << (n_bits - 1 - i);
        }
    }
    *bit_pos += n_bits;
    
    Ok(value)
}

/// Read field value from bits based on field ID type
fn read_field_value(
    bits: &BitSlice<u8, Msb0>,
    bit_pos: &mut usize,
    n_bits: u16,
    fid: FieldId,
) -> Result<FieldValue> {
    let n = n_bits as usize;
    
    // Check if this is an address/bytes field that needs bytes
    let is_bytes_field = matches!(fid, 
        FieldId::Ipv4Src | FieldId::Ipv4Dst | FieldId::Ipv4Dev | FieldId::Ipv4App |
        FieldId::Ipv6Src | FieldId::Ipv6Dst |
        FieldId::Ipv6SrcPrefix | FieldId::Ipv6DstPrefix |
        FieldId::Ipv6DevPrefix | FieldId::Ipv6AppPrefix |
        FieldId::Ipv6SrcIid | FieldId::Ipv6DstIid |
        FieldId::Ipv6DevIid | FieldId::Ipv6AppIid |
        // QUIC connection IDs are variable-length bytes
        FieldId::QuicDcid | FieldId::QuicScid |
        // CoAP Token is variable-length bytes (0-8 bytes based on TKL)
        FieldId::CoapToken |
        // ICMPv6 Payload is variable-length bytes
        FieldId::Icmpv6Payload
    );
    
    if is_bytes_field || n > 64 {
        // Read as bytes
        let byte_len = n.div_ceil(8);
        let mut bytes = vec![0u8; byte_len];
        
        for i in 0..n {
            if *bit_pos + i >= bits.len() {
                return Err(SchcError::Decompression("Not enough bits for address".to_string()));
            }
            if bits[*bit_pos + i] {
                bytes[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        *bit_pos += n;
        
        // Convert to appropriate type
        match fid {
            FieldId::Ipv4Src | FieldId::Ipv4Dst | FieldId::Ipv4Dev | FieldId::Ipv4App if bytes.len() == 4 => {
                Ok(FieldValue::Ipv4(std::net::Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )))
            }
            FieldId::Ipv6Src | FieldId::Ipv6Dst if bytes.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(FieldValue::Ipv6(std::net::Ipv6Addr::from(arr)))
            }
            _ => Ok(FieldValue::Bytes(bytes)),
        }
    } else {
        // Read as numeric value
        let value = read_bits_as_u64(bits, bit_pos, n)?;
        
        Ok(match n {
            1..=8 => FieldValue::U8(value as u8),
            9..=16 => FieldValue::U16(value as u16),
            17..=32 => FieldValue::U32(value as u32),
            _ => FieldValue::U64(value),
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get field size in bits
fn get_field_size_bits(field: &Field) -> u16 {
    // Priority: 1. Explicit FL in rule, 2. FieldId default from JSON
    if let Some(fl) = field.fl {
        return fl;
    }
    field.fid.default_size_bits().unwrap_or(8)
}

/// Get field size in bits, using previously decompressed fields for QUIC CID length lookup
fn get_field_size_bits_with_context(
    field: &Field,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
) -> u16 {
    // Priority: 1. Explicit FL in rule
    if let Some(fl) = field.fl {
        return fl;
    }
    
    // 2. For QUIC connection ID fields, look up length from previously decompressed length field
    match field.fid {
        FieldId::QuicDcid => {
            // DCID length is in bytes, convert to bits
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::QuicDcidLen) {
                return (*len as u16) * 8;
            }
        }
        FieldId::QuicScid => {
            // SCID length is in bytes, convert to bits
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::QuicScidLen) {
                return (*len as u16) * 8;
            }
        }
        FieldId::CoapToken => {
            // CoAP Token length is in bytes (from TKL field), convert to bits
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::CoapTkl) {
                return (*len as u16) * 8;
            }
        }
        _ => {}
    }
    
    // 3. FieldId default from JSON
    field.fid.default_size_bits().unwrap_or(8)
}

/// Convert RuleValue to FieldValue
fn rule_value_to_field_value(rv: &RuleValue, fid: FieldId) -> Result<FieldValue> {
    match rv {
        RuleValue::U64(v) => {
            let bits = fid.default_size_bits().unwrap_or(64);
            Ok(match bits {
                1..=8 => FieldValue::U8(*v as u8),
                9..=16 => FieldValue::U16(*v as u16),
                17..=32 => FieldValue::U32(*v as u32),
                _ => FieldValue::U64(*v),
            })
        }
        RuleValue::Bytes(bytes) => {
            match fid {
                FieldId::Ipv4Src | FieldId::Ipv4Dst | FieldId::Ipv4Dev | FieldId::Ipv4App if bytes.len() == 4 => {
                    Ok(FieldValue::Ipv4(std::net::Ipv4Addr::new(
                        bytes[0], bytes[1], bytes[2], bytes[3]
                    )))
                }
                FieldId::Ipv6Src | FieldId::Ipv6Dst if bytes.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(bytes);
                    Ok(FieldValue::Ipv6(std::net::Ipv6Addr::from(arr)))
                }
                _ => Ok(FieldValue::Bytes(bytes.clone())),
            }
        }
        RuleValue::String(_) => {
            Err(SchcError::Decompression(format!(
                "Cannot convert string TV to field value for {}", fid
            )))
        }
    }
}

// =============================================================================
// Header Building
// =============================================================================

/// Build reconstructed header from decompressed field values
fn build_header(
    fields: &HashMap<FieldId, FieldValue>,
    direction: Direction,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let reconstructed = crate::packet_builder::build_headers(fields, direction, payload)?;
    Ok(reconstructed.data)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{MatchingOperator, Rule, Field};

    fn create_test_rule(rule_id: u32, rule_id_length: u8, fields: Vec<Field>) -> Rule {
        Rule {
            rule_id,
            rule_id_length,
            comment: None,
            compression: fields,
        }
    }

    fn create_field(fid: FieldId, cda: CompressionAction, tv: Option<serde_json::Value>) -> Field {
        let mut f = Field {
            fid,
            fl: None,
            di: None,
            tv: tv.clone(),
            mo: MatchingOperator::Equal,
            cda,
            mo_val: None,
            parsed_tv: None,
        };
        let _ = f.parse_tv();
        f
    }

    // =========================================================================
    // Rule ID Matching Tests
    // =========================================================================

    #[test]
    fn test_match_rule_id_8bit() {
        let rules = vec![
            create_test_rule(1, 8, vec![]),
            create_test_rule(2, 8, vec![]),
        ];

        // Rule ID = 1 (0x01)
        let data = vec![0x01, 0x00];
        let matched = match_rule_id(&data, &rules).unwrap();
        assert_eq!(matched.rule_id, 1);

        // Rule ID = 2 (0x02)
        let data = vec![0x02, 0x00];
        let matched = match_rule_id(&data, &rules).unwrap();
        assert_eq!(matched.rule_id, 2);
    }

    #[test]
    fn test_match_rule_id_variable_length() {
        let rules = vec![
            create_test_rule(0, 2, vec![]),   // 2-bit: 00
            create_test_rule(1, 2, vec![]),   // 2-bit: 01
            create_test_rule(4, 3, vec![]),   // 3-bit: 100
            create_test_rule(12, 4, vec![]),  // 4-bit: 1100
        ];

        // 2-bit rule ID = 0 (binary: 00...)
        let data = vec![0b00000000];
        let matched = match_rule_id(&data, &rules).unwrap();
        assert_eq!(matched.rule_id, 0);
        assert_eq!(matched.rule_id_length, 2);

        // 4-bit rule ID = 12 (binary: 1100...)
        let data = vec![0b11000000];
        let matched = match_rule_id(&data, &rules).unwrap();
        assert_eq!(matched.rule_id, 12);
        assert_eq!(matched.rule_id_length, 4);
    }

    #[test]
    fn test_match_rule_id_no_match() {
        let rules = vec![
            create_test_rule(1, 8, vec![]),
        ];

        let data = vec![0x02];
        let result = match_rule_id(&data, &rules);
        assert!(result.is_err());
    }

    // =========================================================================
    // Bit Reading Tests
    // =========================================================================

    #[test]
    fn test_read_bits_as_u64() {
        let data = vec![0b10110100, 0b11001010];
        let bits = BitSlice::<_, Msb0>::from_slice(&data);
        
        let mut pos = 0;
        
        // Read 4 bits: 1011
        let val = read_bits_as_u64(bits, &mut pos, 4).unwrap();
        assert_eq!(val, 0b1011);
        assert_eq!(pos, 4);
        
        // Read 8 bits: 01001100
        let val = read_bits_as_u64(bits, &mut pos, 8).unwrap();
        assert_eq!(val, 0b01001100);
        assert_eq!(pos, 12);
    }

    // =========================================================================
    // CDA Decompression Tests
    // =========================================================================

    #[test]
    fn test_decompress_not_sent() {
        let field = create_field(
            FieldId::Ipv6Ver,
            CompressionAction::NotSent,
            Some(serde_json::json!(6)),
        );

        let result = restore_from_tv(&field).unwrap();
        match result {
            FieldValue::U8(v) => assert_eq!(v, 6),
            _ => panic!("Expected U8"),
        }
    }

    #[test]
    fn test_decompress_value_sent() {
        let data = vec![0x1F, 0x90]; // 8080 in big-endian
        let bits = BitSlice::<_, Msb0>::from_slice(&data);
        let mut pos = 0;

        let result = read_field_value(bits, &mut pos, 16, FieldId::UdpSrcPort).unwrap();
        match result {
            FieldValue::U16(v) => assert_eq!(v, 0x1F90), // 8080
            _ => panic!("Expected U16"),
        }
    }

    #[test]
    fn test_decompress_mapping_sent() {
        let mut field = Field {
            fid: FieldId::Ipv6HopLmt,
            fl: None,
            di: None,
            tv: Some(serde_json::json!([64, 128, 255])),
            mo: MatchingOperator::MatchMapping,
            cda: CompressionAction::MappingSent,
            mo_val: None,
            parsed_tv: None,
        };
        let _ = field.parse_tv();

        // Index 1 (binary: 01) -> should get 128
        let data = vec![0b01000000];
        let bits = BitSlice::<_, Msb0>::from_slice(&data);
        let mut pos = 0;

        let result = decompress_mapping(bits, &mut pos, &field).unwrap();
        match result {
            FieldValue::U8(v) => assert_eq!(v, 128),
            _ => panic!("Expected U8"),
        }
        assert_eq!(pos, 2); // 2 bits consumed for index into 3-element array
    }
}
