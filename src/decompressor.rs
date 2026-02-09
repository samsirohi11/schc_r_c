//! Decompression Logic
//!
//! Implements the SCHC Decompression Actions for converting compressed
//! SCHC packets back into original packet headers.

use bitvec::prelude::*;
use std::collections::HashMap;

use crate::bit_buffer::BitBuffer;
use crate::error::{Result, SchcError};
use crate::field_id::FieldId;
use crate::parser::{Direction, FieldValue};
use crate::rule::{CompressionAction, Field, FieldLength, ParsedTargetValue, Rule, RuleValue};

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
        return Err(SchcError::Decompression(
            "Empty compressed data".to_string(),
        ));
    }

    let bits = BitSlice::<_, Msb0>::from_slice(data);

    // Sort rules by rule_id_length descending for proper variable-length matching
    let mut sorted_rules: Vec<&Rule> = Vec::with_capacity(rules.len());
    sorted_rules.extend(rules.iter());
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

    Err(SchcError::Decompression(
        "No matching rule ID found".to_string(),
    ))
}

// =============================================================================
// Main Decompression Entry Point
// =============================================================================

/// Decompress a SCHC packet using the provided rules
///
/// # Arguments
/// * `compressed_data` - The compressed SCHC packet (rule ID + residues + payload)
/// * `rules` - Available SCHC compression rules
/// * `direction` - Packet direction (for directional field reconstruction)
/// * `original_payload` - Optional explicit payload to append (if None, extracts from compressed_data)
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

    let mut buf = BitBuffer::from_bytes(compressed_data);
    buf.set_position(rule.rule_id_length as usize);

    // Decompress each field according to its CDA
    // Pass already-decompressed fields for context-dependent length lookup
    // Skip fields that don't match the current direction (DI filtering)
    let mut fields: HashMap<FieldId, FieldValue> = HashMap::with_capacity(rule.compression.len());

    for field in &rule.compression {
        let field_applies = match field.di {
            None => true,
            Some(field_dir) => field_dir == direction,
        };

        if !field_applies {
            continue;
        }

        let value = decompress_field(&mut buf, field, &fields, &rule.compression)?;
        fields.insert(field.fid, value);
    }

    let bit_pos = buf.position();

    // Extract payload from compressed data
    let residue_bytes = bit_pos.div_ceil(8);
    let extracted_payload: &[u8] = if residue_bytes < compressed_data.len() {
        &compressed_data[residue_bytes..]
    } else {
        &[]
    };

    let payload = original_payload.unwrap_or(extracted_payload);

    let header_data = build_header(&fields, direction, Some(payload))?;

    let mut full_data = header_data.clone();
    full_data.extend_from_slice(payload);

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
    buf: &mut BitBuffer,
    field: &Field,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
    rule_entries: &[Field],
) -> Result<FieldValue> {
    match field.cda {
        CompressionAction::NotSent => restore_from_tv(field),
        CompressionAction::ValueSent => {
            let field_bits =
                get_field_size_bits_with_context_and_rule(field, decompressed_fields, rule_entries);
            read_field_value(buf, field_bits, field.fid)
        }
        CompressionAction::MappingSent => decompress_mapping(buf, field),
        CompressionAction::Lsb => decompress_lsb(buf, field),
        CompressionAction::Compute => Ok(FieldValue::ComputePlaceholder),
    }
}

/// Restore field value from Target Value (for not-sent CDA)
fn restore_from_tv(field: &Field) -> Result<FieldValue> {
    match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => rule_value_to_field_value(rv, field.fid),
        Some(ParsedTargetValue::Mapping(_)) => Err(SchcError::Decompression(format!(
            "Field {} has not-sent CDA but mapping TV",
            field.fid
        ))),
        None => Err(SchcError::Decompression(format!(
            "Field {} has not-sent CDA but no TV",
            field.fid
        ))),
    }
}

/// Decompress mapping-sent field (read index, lookup TV)
fn decompress_mapping(buf: &mut BitBuffer, field: &Field) -> Result<FieldValue> {
    if let Some(ParsedTargetValue::Mapping(tv_list)) = &field.parsed_tv {
        let num_items = tv_list.len();
        if num_items == 0 {
            return Err(SchcError::Decompression(format!(
                "Field {} has empty mapping",
                field.fid
            )));
        }

        let index_bits = if num_items <= 1 {
            0
        } else {
            (usize::BITS - (num_items - 1).leading_zeros()) as usize
        };

        let index = if index_bits > 0 {
            buf.read_bits(index_bits).ok_or_else(|| {
                SchcError::Decompression(format!(
                    "Field {} not enough bits for mapping index",
                    field.fid
                ))
            })? as usize
        } else {
            0
        };

        if index >= tv_list.len() {
            return Err(SchcError::Decompression(format!(
                "Field {} mapping index {} out of bounds (max: {})",
                field.fid,
                index,
                tv_list.len() - 1
            )));
        }

        rule_value_to_field_value(&tv_list[index], field.fid)
    } else {
        Err(SchcError::Decompression(format!(
            "Field {} has mapping-sent CDA but no mapping TV",
            field.fid
        )))
    }
}

/// Decompress LSB field (combine MSB from TV + LSB from residue)
fn decompress_lsb(buf: &mut BitBuffer, field: &Field) -> Result<FieldValue> {
    let msb_bits = field.mo_val.unwrap_or(0) as usize;
    let field_size = get_field_size_bits(field) as usize;

    if msb_bits > field_size {
        return Err(SchcError::Decompression(format!(
            "Field {} MSB bits ({}) exceeds field size ({})",
            field.fid, msb_bits, field_size
        )));
    }

    let lsb_bits = field_size - msb_bits;

    let msb_value = match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => match rv {
            RuleValue::U64(v) => *v,
            _ => {
                return Err(SchcError::Decompression(format!(
                    "Field {} has non-numeric TV for LSB",
                    field.fid
                )))
            }
        },
        _ => {
            return Err(SchcError::Decompression(format!(
                "Field {} has LSB CDA but no TV",
                field.fid
            )))
        }
    };

    let lsb_value = buf.read_bits(lsb_bits).ok_or_else(|| {
        SchcError::Decompression(format!("Field {} not enough bits for LSB", field.fid))
    })?;

    let msb_mask = ((1u64 << msb_bits) - 1) << lsb_bits;
    let combined = (msb_value & msb_mask) | lsb_value;

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

/// Read field value from BitBuffer based on field ID type
fn read_field_value(buf: &mut BitBuffer, n_bits: u16, fid: FieldId) -> Result<FieldValue> {
    let n = n_bits as usize;

    // Check if this is an address/bytes field that needs bytes
    let is_bytes_field = matches!(
        fid,
        FieldId::Ipv4Src
            | FieldId::Ipv4Dst
            | FieldId::Ipv4Dev
            | FieldId::Ipv4App
            | FieldId::Ipv6Src
            | FieldId::Ipv6Dst
            | FieldId::Ipv6SrcPrefix
            | FieldId::Ipv6DstPrefix
            | FieldId::Ipv6DevPrefix
            | FieldId::Ipv6AppPrefix
            | FieldId::Ipv6SrcIid
            | FieldId::Ipv6DstIid
            | FieldId::Ipv6DevIid
            | FieldId::Ipv6AppIid
            | FieldId::QuicDcid
            | FieldId::QuicScid
            | FieldId::CoapToken
            | FieldId::Icmpv6Payload
    );

    if is_bytes_field || n > 64 {
        let bytes = buf
            .read_bits_as_bytes(n)
            .ok_or_else(|| SchcError::Decompression("Not enough bits for field".to_string()))?;

        match fid {
            FieldId::Ipv4Src | FieldId::Ipv4Dst | FieldId::Ipv4Dev | FieldId::Ipv4App
                if bytes.len() == 4 =>
            {
                Ok(FieldValue::Ipv4(std::net::Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
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
        let value = buf.read_bits(n).ok_or_else(|| {
            SchcError::Decompression(format!(
                "Not enough bits: need {} at position {}, have {}",
                n,
                buf.position(),
                buf.remaining() + buf.position()
            ))
        })?;

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

/// Get field size in bits, using previously decompressed fields for context-dependent length
fn get_field_size_bits_with_context(
    field: &Field,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
) -> u16 {
    // Priority: 1. fl_func (dynamic length function)
    if let Some(ref fl_func) = field.fl_func
        && let Some(bits) = resolve_field_length(fl_func, decompressed_fields)
    {
        return bits;
    }

    // 2. Explicit FL in rule
    if let Some(fl) = field.fl {
        return fl;
    }

    // 3. Hardcoded context lookups (fallback for rules without fl_func)
    match field.fid {
        FieldId::QuicDcid => {
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::QuicDcidLen) {
                return (*len as u16) * 8;
            }
        }
        FieldId::QuicScid => {
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::QuicScidLen) {
                return (*len as u16) * 8;
            }
        }
        FieldId::CoapToken => {
            if let Some(FieldValue::U8(len)) = decompressed_fields.get(&FieldId::CoapTkl) {
                return (*len as u16) * 8;
            }
        }
        _ => {}
    }

    // 4. FieldId default from JSON
    field.fid.default_size_bits().unwrap_or(8)
}

/// Resolve a FieldLength function to a concrete bit length using decompressed field context
/// Note: LengthBytes/LengthBits require the rule's entry list for index resolution;
/// use resolve_field_length_with_rule when the rule is available.
fn resolve_field_length(
    fl_func: &FieldLength,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
) -> Option<u16> {
    match fl_func {
        FieldLength::Fixed(bits) => Some(*bits),
        FieldLength::TokenLength => {
            if let Some(FieldValue::U8(tkl)) = decompressed_fields.get(&FieldId::CoapTkl) {
                Some((*tkl as u16) * 8)
            } else {
                None
            }
        }
        // LengthBytes/LengthBits need rule context — return None to fall through
        FieldLength::LengthBytes(_) | FieldLength::LengthBits(_) => None,
        FieldLength::Variable => None,
    }
}

/// Resolve a field length from a previously decompressed field by entry index
/// multiplier: 8 for bytes→bits, 1 for bits→bits
fn resolve_length_by_index_with_rule(
    entry_idx: usize,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
    multiplier: u16,
    rule_entries: &[Field],
) -> Option<u16> {
    // Map entry index → FieldId from rule's compression list
    let ref_field = rule_entries.get(entry_idx)?;
    let ref_value = decompressed_fields.get(&ref_field.fid)?;
    let len = field_value_as_u16(ref_value)?;
    Some(len * multiplier)
}

/// Extract a u16 value from a FieldValue (for length resolution)
fn field_value_as_u16(value: &FieldValue) -> Option<u16> {
    match value {
        FieldValue::U8(v) => Some(*v as u16),
        FieldValue::U16(v) => Some(*v),
        FieldValue::U32(v) => Some(*v as u16),
        FieldValue::U64(v) => Some(*v as u16),
        _ => None,
    }
}

/// Get field size with full rule context for entry-index-based FieldLength resolution
fn get_field_size_bits_with_context_and_rule(
    field: &Field,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
    rule_entries: &[Field],
) -> u16 {
    // Priority: 1. fl_func (dynamic length function)
    if let Some(ref fl_func) = field.fl_func
        && let Some(bits) =
            resolve_field_length_with_rule(fl_func, decompressed_fields, rule_entries)
    {
        return bits;
    }

    // Fall through to existing context resolution
    get_field_size_bits_with_context(field, decompressed_fields)
}

/// Resolve a FieldLength function with full rule context
fn resolve_field_length_with_rule(
    fl_func: &FieldLength,
    decompressed_fields: &HashMap<FieldId, FieldValue>,
    rule_entries: &[Field],
) -> Option<u16> {
    match fl_func {
        FieldLength::Fixed(bits) => Some(*bits),
        FieldLength::TokenLength => {
            if let Some(FieldValue::U8(tkl)) = decompressed_fields.get(&FieldId::CoapTkl) {
                Some((*tkl as u16) * 8)
            } else {
                None
            }
        }
        FieldLength::LengthBytes(entry_idx) => {
            resolve_length_by_index_with_rule(*entry_idx, decompressed_fields, 8, rule_entries)
        }
        FieldLength::LengthBits(entry_idx) => {
            resolve_length_by_index_with_rule(*entry_idx, decompressed_fields, 1, rule_entries)
        }
        FieldLength::Variable => None,
    }
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
        RuleValue::Bytes(bytes) => match fid {
            FieldId::Ipv4Src | FieldId::Ipv4Dst | FieldId::Ipv4Dev | FieldId::Ipv4App
                if bytes.len() == 4 =>
            {
                Ok(FieldValue::Ipv4(std::net::Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )))
            }
            FieldId::Ipv6Src | FieldId::Ipv6Dst if bytes.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Ok(FieldValue::Ipv6(std::net::Ipv6Addr::from(arr)))
            }
            _ => Ok(FieldValue::Bytes(bytes.clone())),
        },
        RuleValue::String(s) => {
            // String TVs are used for CoAP options like Uri-Path
            // Convert to bytes for field value
            Ok(FieldValue::Bytes(s.as_bytes().to_vec()))
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
    use crate::rule::{Field, MatchingOperator, Rule};

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
            fl_func: None,
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
            create_test_rule(0, 2, vec![]),  // 2-bit: 00
            create_test_rule(1, 2, vec![]),  // 2-bit: 01
            create_test_rule(4, 3, vec![]),  // 3-bit: 100
            create_test_rule(12, 4, vec![]), // 4-bit: 1100
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
        let rules = vec![create_test_rule(1, 8, vec![])];

        let data = vec![0x02];
        let result = match_rule_id(&data, &rules);
        assert!(result.is_err());
    }

    // =========================================================================
    // Bit Reading Tests (using BitBuffer)
    // =========================================================================

    #[test]
    fn test_read_bits_via_bitbuffer() {
        let data = vec![0b10110100, 0b11001010];
        let mut buf = BitBuffer::from_bytes(&data);

        // Read 4 bits: 1011
        let val = buf.read_bits(4).unwrap();
        assert_eq!(val, 0b1011);
        assert_eq!(buf.position(), 4);

        // Read 8 bits: 01001100
        let val = buf.read_bits(8).unwrap();
        assert_eq!(val, 0b01001100);
        assert_eq!(buf.position(), 12);
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
        let mut buf = BitBuffer::from_bytes(&data);

        let result = read_field_value(&mut buf, 16, FieldId::UdpSrcPort).unwrap();
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
            fl_func: None,
        };
        let _ = field.parse_tv();

        // Index 1 (binary: 01) -> should get 128
        let data = vec![0b01000000];
        let mut buf = BitBuffer::from_bytes(&data);

        let result = decompress_mapping(&mut buf, &field).unwrap();
        match result {
            FieldValue::U8(v) => assert_eq!(v, 128),
            _ => panic!("Expected U8"),
        }
        assert_eq!(buf.position(), 2); // 2 bits consumed for index into 3-element array
    }
}
