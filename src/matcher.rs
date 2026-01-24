//! Field Matching Logic
//!
//! Provides functions to match packet field values against rule target values
//! using various matching operators (equal, ignore, match-mapping, MSB).

use crate::field_id::FieldId;
use crate::parser::FieldValue;
use crate::rule::{MatchingOperator, RuleValue};
use crate::tree::BranchInfo;
use crate::parser::StreamingParser;

// =============================================================================
// Value Matching Functions
// =============================================================================

/// Check if a packet value matches a target value (exact match)
#[inline]
pub fn values_match(packet_value: &FieldValue, target_value: &RuleValue) -> bool {
    match (packet_value, target_value) {
        // ComputePlaceholder never matches any value
        (FieldValue::ComputePlaceholder, _) => false,
        (FieldValue::U8(p), RuleValue::U64(t)) => *p as u64 == *t,
        (FieldValue::U16(p), RuleValue::U64(t)) => *p as u64 == *t,
        (FieldValue::U32(p), RuleValue::U64(t)) => *p as u64 == *t,
        (FieldValue::U64(p), RuleValue::U64(t)) => *p == *t,
        (FieldValue::Bytes(p), RuleValue::Bytes(t)) => p == t,
        // String option values (e.g., CoAP Uri-Path) - compare bytes to string bytes
        (FieldValue::Bytes(p), RuleValue::String(t)) => p == t.as_bytes(),
        (FieldValue::Ipv6(p_addr), RuleValue::Bytes(t_prefix)) => {
            let p_bytes = p_addr.octets();
            p_bytes.starts_with(t_prefix)
        }
        (FieldValue::Ipv4(p_addr), RuleValue::Bytes(t_bytes)) => {
            let p_bytes = p_addr.octets();
            // Full address match (4 bytes) or prefix match
            if t_bytes.len() == 4 {
                p_bytes == t_bytes.as_slice()
            } else {
                p_bytes.starts_with(t_bytes)
            }
        }
        _ => false,
    }
}

/// Check if packet value matches target value on MSB bits
#[inline]
pub fn msb_match(pv: &FieldValue, tv: &RuleValue, bits: u8, fid: FieldId) -> bool {
    // ComputePlaceholder never matches
    if matches!(pv, FieldValue::ComputePlaceholder) {
        return false;
    }

    let packet_num = match pv {
        FieldValue::U8(v) => *v as u64,
        FieldValue::U16(v) => *v as u64,
        FieldValue::U32(v) => *v as u64,
        FieldValue::U64(v) => *v,
        _ => return false,
    };

    let RuleValue::U64(target_num) = tv else {
        return false;
    };

    // Get the actual field size from the FieldId (e.g., 16 for UDP port)
    let field_bits = fid.default_size_bits().unwrap_or(64) as u8;
    if bits > field_bits {
        return false;
    }

    // Shift to keep only the MSB bits, comparing within actual field size
    let shift = field_bits - bits;
    (packet_num >> shift) == (target_num >> shift)
}

// =============================================================================
// Branch Matching
// =============================================================================

/// Result of checking a branch match
pub enum BranchMatchResult {
    /// Field matched - contains the parsed field value
    Matched(Option<FieldValue>),
    /// Field didn't match - contains the parsed field value for debug display
    NotMatched(Option<FieldValue>),
    /// Direction Indicator mismatch - skip this field entirely, continue to children
    DiSkip,
}

/// Check if a packet field matches a branch in the rule tree
/// Returns a BranchMatchResult indicating match status or DI skip
#[inline]
pub fn check_branch_match(parser: &mut StreamingParser, info: &BranchInfo) -> BranchMatchResult {
    // Check Direction Indicator (DI) - if branch specifies a direction, it must match packet direction
    // None (bidirectional) matches any packet direction
    if let Some(branch_di) = info.di
        && branch_di != parser.direction()
    {
        return BranchMatchResult::DiSkip;
    }

    // For QUIC.DCID on short headers, set the expected length from the rule's target value
    // This allows us to parse the correct number of bytes for matching
    if info.fid == FieldId::QuicDcid
        && let Some(RuleValue::Bytes(tv_bytes)) = &info.tv {
            parser.set_quic_dcid_len(tv_bytes.len() as u8);
        }

    let packet_value = match parser.parse_field(info.fid) {
        Ok(Some(v)) => v.clone(),
        Ok(None) => return BranchMatchResult::NotMatched(None),
        Err(_) => return BranchMatchResult::NotMatched(None),
    };

    let matched = match info.mo {
        MatchingOperator::Ignore => true,
        MatchingOperator::Equal => {
            if let Some(tv) = &info.tv {
                values_match(&packet_value, tv)
            } else {
                false
            }
        }
        MatchingOperator::MatchMapping => {
            // Check if packet value matches ANY of the mapping values
            if let Some(mapping_values) = &info.mapping_tv {
                mapping_values.iter().any(|tv| values_match(&packet_value, tv))
            } else {
                false
            }
        }
        MatchingOperator::Msb(bits) => {
            if let Some(tv) = &info.tv {
                msb_match(&packet_value, tv, bits, info.fid)
            } else {
                false
            }
        }
    };

    if matched {
        BranchMatchResult::Matched(Some(packet_value))
    } else {
        BranchMatchResult::NotMatched(Some(packet_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // =========================================================================
    // values_match tests
    // =========================================================================

    #[test]
    fn test_values_match_u8() {
        let pv = FieldValue::U8(42);
        let tv = RuleValue::U64(42);
        assert!(values_match(&pv, &tv));
        
        let tv_wrong = RuleValue::U64(43);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_u16() {
        let pv = FieldValue::U16(5060);
        let tv = RuleValue::U64(5060);
        assert!(values_match(&pv, &tv));
        
        let tv_wrong = RuleValue::U64(5061);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_u32() {
        let pv = FieldValue::U32(0x12345678);
        let tv = RuleValue::U64(0x12345678);
        assert!(values_match(&pv, &tv));
        
        let tv_wrong = RuleValue::U64(0x12345679);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_u64() {
        let pv = FieldValue::U64(0xDEADBEEFCAFEBABE);
        let tv = RuleValue::U64(0xDEADBEEFCAFEBABE);
        assert!(values_match(&pv, &tv));
        
        let tv_wrong = RuleValue::U64(0xDEADBEEFCAFEBABF);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_bytes() {
        let pv = FieldValue::Bytes(vec![0x01, 0x02, 0x03, 0x04]);
        let tv = RuleValue::Bytes(vec![0x01, 0x02, 0x03, 0x04]);
        assert!(values_match(&pv, &tv));
        
        let tv_wrong = RuleValue::Bytes(vec![0x01, 0x02, 0x03, 0x05]);
        assert!(!values_match(&pv, &tv_wrong));
        
        // Different length
        let tv_short = RuleValue::Bytes(vec![0x01, 0x02, 0x03]);
        assert!(!values_match(&pv, &tv_short));
    }

    #[test]
    fn test_values_match_ipv6_prefix() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let pv = FieldValue::Ipv6(addr);
        let prefix: Vec<u8> = vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];
        let tv = RuleValue::Bytes(prefix);
        assert!(values_match(&pv, &tv));
        
        // Wrong prefix
        let wrong_prefix: Vec<u8> = vec![0x20, 0x01, 0x0d, 0xb9, 0x00, 0x00, 0x00, 0x00];
        let tv_wrong = RuleValue::Bytes(wrong_prefix);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_ipv6_short_prefix() {
        // Match on shorter prefix (e.g., /32)
        let addr: Ipv6Addr = "2001:db8:abcd:1234::1".parse().unwrap();
        let pv = FieldValue::Ipv6(addr);
        let prefix_32: Vec<u8> = vec![0x20, 0x01, 0x0d, 0xb8];
        let tv = RuleValue::Bytes(prefix_32);
        assert!(values_match(&pv, &tv));
    }

    #[test]
    fn test_values_match_ipv4_prefix() {
        let addr: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let pv = FieldValue::Ipv4(addr);
        
        // Match /24 prefix
        let prefix: Vec<u8> = vec![192, 168, 1];
        let tv = RuleValue::Bytes(prefix);
        assert!(values_match(&pv, &tv));
        
        // Wrong /24 prefix
        let wrong_prefix: Vec<u8> = vec![192, 168, 2];
        let tv_wrong = RuleValue::Bytes(wrong_prefix);
        assert!(!values_match(&pv, &tv_wrong));
    }

    #[test]
    fn test_values_match_type_mismatch() {
        // U8 vs Bytes should not match
        let pv = FieldValue::U8(42);
        let tv = RuleValue::Bytes(vec![42]);
        assert!(!values_match(&pv, &tv));
        
        // Bytes vs U64 should not match
        let pv2 = FieldValue::Bytes(vec![0, 0, 0, 42]);
        let tv2 = RuleValue::U64(42);
        assert!(!values_match(&pv2, &tv2));
    }

    #[test]
    fn test_values_match_boundary_values() {
        // Test max values
        let pv_max_u8 = FieldValue::U8(255);
        let tv_max_u8 = RuleValue::U64(255);
        assert!(values_match(&pv_max_u8, &tv_max_u8));
        
        let pv_max_u16 = FieldValue::U16(65535);
        let tv_max_u16 = RuleValue::U64(65535);
        assert!(values_match(&pv_max_u16, &tv_max_u16));
        
        // Test zero
        let pv_zero = FieldValue::U8(0);
        let tv_zero = RuleValue::U64(0);
        assert!(values_match(&pv_zero, &tv_zero));
    }

    // =========================================================================
    // msb_match tests
    // =========================================================================

    #[test]
    fn test_msb_match_basic() {
        let pv = FieldValue::U16(0xAB12);
        let tv = RuleValue::U64(0xAB00);
        // Top 8 bits: 0xAB should match
        assert!(msb_match(&pv, &tv, 8, FieldId::UdpSrcPort));
        // Top 12 bits: 0xAB1 vs 0xAB0 should not match
        assert!(!msb_match(&pv, &tv, 12, FieldId::UdpSrcPort));
    }

    #[test]
    fn test_msb_match_exact() {
        let pv = FieldValue::U16(0x1234);
        let tv = RuleValue::U64(0x1234);
        // All 16 bits should match exactly
        assert!(msb_match(&pv, &tv, 16, FieldId::UdpSrcPort));
    }

    #[test]
    fn test_msb_match_single_bit() {
        // Test single MSB bit matching
        let pv_high = FieldValue::U16(0x8000);  // MSB = 1
        let tv_high = RuleValue::U64(0x8000);
        assert!(msb_match(&pv_high, &tv_high, 1, FieldId::UdpSrcPort));
        
        let pv_low = FieldValue::U16(0x7FFF);  // MSB = 0
        assert!(!msb_match(&pv_low, &tv_high, 1, FieldId::UdpSrcPort));
    }

    #[test]
    fn test_msb_match_u8() {
        let pv = FieldValue::U8(0b11110000);
        let tv = RuleValue::U64(0b11110000);
        // Match top 4 bits (for an 8-bit field)
        assert!(msb_match(&pv, &tv, 4, FieldId::Ipv4Ttl));
        
        let pv2 = FieldValue::U8(0b11111111);
        assert!(msb_match(&pv2, &tv, 4, FieldId::Ipv4Ttl)); // Top 4 bits are still 1111
    }

    #[test]
    fn test_msb_match_u32() {
        // IPv6 Flow Label is 20 bits
        // To match MSB 16 bits, we shift by (20 - 16) = 4
        // 0x12345 >> 4 = 0x1234, 0x12340 >> 4 = 0x1234 -> should match
        let pv = FieldValue::U32(0x12345);  // 20-bit value: 0x12345
        let tv = RuleValue::U64(0x12340);   // Top 16 bits: 0x1234
        assert!(msb_match(&pv, &tv, 16, FieldId::Ipv6Fl));
    }

    #[test]
    fn test_msb_match_bits_exceeds_field() {
        // Requesting more bits than field size should fail
        let pv = FieldValue::U8(0xFF);
        let tv = RuleValue::U64(0xFF);
        assert!(!msb_match(&pv, &tv, 16, FieldId::Ipv4Ttl)); // 16 > 8-bit TTL
    }

    #[test]
    fn test_msb_match_wrong_target_type() {
        // RuleValue::Bytes should not work with msb_match
        let pv = FieldValue::U16(0x1234);
        let tv = RuleValue::Bytes(vec![0x12, 0x34]);
        assert!(!msb_match(&pv, &tv, 8, FieldId::UdpSrcPort));
    }

    #[test]
    fn test_msb_match_non_numeric_field() {
        // Bytes field should not match
        let pv = FieldValue::Bytes(vec![0x12, 0x34]);
        let tv = RuleValue::U64(0x1234);
        assert!(!msb_match(&pv, &tv, 8, FieldId::UdpSrcPort));
    }

    #[test]
    fn test_msb_match_zero_bits() {
        // Zero bits means everything matches (trivially true)
        let pv = FieldValue::U16(0xFFFF);
        let tv = RuleValue::U64(0x0000);
        assert!(msb_match(&pv, &tv, 0, FieldId::UdpSrcPort));
    }
}
