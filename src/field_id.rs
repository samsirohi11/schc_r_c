//! Field identifier enum for compile-time type safety and performance.
//!
//! This module includes the auto-generated FieldId enum from field-context.json.
//! The build.rs script parses the JSON and generates the enum at compile time,
//! making field-context.json the single source of truth.
//!
//! Using an enum instead of strings provides:
//! - Zero-cost comparisons (enum variants vs string comparison)
//! - Compile-time validation of field names
//! - No heap allocation for field identifiers

// Include the auto-generated FieldId enum and implementations
include!(concat!(env!("OUT_DIR"), "/field_id_generated.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // as_str tests
    // =========================================================================

    #[test]
    fn test_ipv4_field_strings() {
        assert_eq!(FieldId::Ipv4Ver.as_str(), "IPV4.VER");
        assert_eq!(FieldId::Ipv4Ihl.as_str(), "IPV4.IHL");
        assert_eq!(FieldId::Ipv4Dscp.as_str(), "IPV4.DSCP");
        assert_eq!(FieldId::Ipv4Ecn.as_str(), "IPV4.ECN");
        assert_eq!(FieldId::Ipv4Len.as_str(), "IPV4.LEN");
        assert_eq!(FieldId::Ipv4Id.as_str(), "IPV4.ID");
        assert_eq!(FieldId::Ipv4Flags.as_str(), "IPV4.FLAGS");
        assert_eq!(FieldId::Ipv4FragOff.as_str(), "IPV4.FRAG_OFF");
        assert_eq!(FieldId::Ipv4Ttl.as_str(), "IPV4.TTL");
        assert_eq!(FieldId::Ipv4Proto.as_str(), "IPV4.PROTO");
        assert_eq!(FieldId::Ipv4Chksum.as_str(), "IPV4.CHKSUM");
        assert_eq!(FieldId::Ipv4Src.as_str(), "IPV4.SRC");
        assert_eq!(FieldId::Ipv4Dst.as_str(), "IPV4.DST");
    }

    #[test]
    fn test_ipv6_field_strings() {
        assert_eq!(FieldId::Ipv6Ver.as_str(), "IPV6.VER");
        assert_eq!(FieldId::Ipv6Tc.as_str(), "IPV6.TC");
        assert_eq!(FieldId::Ipv6Fl.as_str(), "IPV6.FL");
        assert_eq!(FieldId::Ipv6Len.as_str(), "IPV6.LEN");
        assert_eq!(FieldId::Ipv6Nxt.as_str(), "IPV6.NXT");
        assert_eq!(FieldId::Ipv6HopLmt.as_str(), "IPV6.HOP_LMT");
        assert_eq!(FieldId::Ipv6DevPrefix.as_str(), "IPV6.DEV_PREFIX");
        assert_eq!(FieldId::Ipv6DevIid.as_str(), "IPV6.DEV_IID");
        assert_eq!(FieldId::Ipv6AppPrefix.as_str(), "IPV6.APP_PREFIX");
        assert_eq!(FieldId::Ipv6AppIid.as_str(), "IPV6.APP_IID");
    }

    #[test]
    fn test_udp_field_strings() {
        assert_eq!(FieldId::UdpSrcPort.as_str(), "UDP.SRC_PORT");
        assert_eq!(FieldId::UdpDstPort.as_str(), "UDP.DST_PORT");
        assert_eq!(FieldId::UdpLen.as_str(), "UDP.LEN");
        assert_eq!(FieldId::UdpCksum.as_str(), "UDP.CKSUM");
        assert_eq!(FieldId::UdpDevPort.as_str(), "UDP.DEV_PORT");
        assert_eq!(FieldId::UdpAppPort.as_str(), "UDP.APP_PORT");
    }

    // =========================================================================
    // FromStr tests
    // =========================================================================

    #[test]
    fn test_parse_ipv4_fields() {
        assert_eq!(FieldId::from_str("IPV4.VER").unwrap(), FieldId::Ipv4Ver);
        assert_eq!(FieldId::from_str("IPV4.TTL").unwrap(), FieldId::Ipv4Ttl);
        assert_eq!(FieldId::from_str("IPV4.SRC").unwrap(), FieldId::Ipv4Src);
    }

    #[test]
    fn test_parse_ipv6_fields() {
        assert_eq!(FieldId::from_str("IPV6.VER").unwrap(), FieldId::Ipv6Ver);
        assert_eq!(FieldId::from_str("IPV6.HOP_LMT").unwrap(), FieldId::Ipv6HopLmt);
        assert_eq!(FieldId::from_str("IPV6.DEV_PREFIX").unwrap(), FieldId::Ipv6DevPrefix);
    }

    #[test]
    fn test_parse_udp_fields() {
        assert_eq!(FieldId::from_str("UDP.SRC_PORT").unwrap(), FieldId::UdpSrcPort);
        assert_eq!(FieldId::from_str("UDP.CKSUM").unwrap(), FieldId::UdpCksum);
    }

    #[test]
    fn test_parse_unknown_field() {
        let result = FieldId::from_str("UNKNOWN.FIELD");
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert_eq!(err.0, "UNKNOWN.FIELD");
    }

    #[test]
    fn test_parse_case_sensitive() {
        // Field IDs are case-sensitive
        assert!(FieldId::from_str("ipv4.ver").is_err());
        assert!(FieldId::from_str("Ipv6.Ver").is_err());
    }

    // =========================================================================
    // default_size_bits tests
    // =========================================================================

    #[test]
    fn test_ipv4_field_sizes() {
        assert_eq!(FieldId::Ipv4Ver.default_size_bits(), Some(4));
        assert_eq!(FieldId::Ipv4Ihl.default_size_bits(), Some(4));
        assert_eq!(FieldId::Ipv4Dscp.default_size_bits(), Some(6));
        assert_eq!(FieldId::Ipv4Ecn.default_size_bits(), Some(2));
        assert_eq!(FieldId::Ipv4Len.default_size_bits(), Some(16));
        assert_eq!(FieldId::Ipv4Id.default_size_bits(), Some(16));
        assert_eq!(FieldId::Ipv4Flags.default_size_bits(), Some(3));
        assert_eq!(FieldId::Ipv4FragOff.default_size_bits(), Some(13));
        assert_eq!(FieldId::Ipv4Ttl.default_size_bits(), Some(8));
        assert_eq!(FieldId::Ipv4Proto.default_size_bits(), Some(8));
        assert_eq!(FieldId::Ipv4Chksum.default_size_bits(), Some(16));
        assert_eq!(FieldId::Ipv4Src.default_size_bits(), Some(32));
        assert_eq!(FieldId::Ipv4Dst.default_size_bits(), Some(32));
    }

    #[test]
    fn test_ipv6_field_sizes() {
        assert_eq!(FieldId::Ipv6Ver.default_size_bits(), Some(4));
        assert_eq!(FieldId::Ipv6Tc.default_size_bits(), Some(8));
        assert_eq!(FieldId::Ipv6Fl.default_size_bits(), Some(20));
        assert_eq!(FieldId::Ipv6Len.default_size_bits(), Some(16));
        assert_eq!(FieldId::Ipv6Nxt.default_size_bits(), Some(8));
        assert_eq!(FieldId::Ipv6HopLmt.default_size_bits(), Some(8));
        assert_eq!(FieldId::Ipv6DevPrefix.default_size_bits(), Some(64));
        assert_eq!(FieldId::Ipv6DevIid.default_size_bits(), Some(64));
    }

    #[test]
    fn test_udp_field_sizes() {
        assert_eq!(FieldId::UdpSrcPort.default_size_bits(), Some(16));
        assert_eq!(FieldId::UdpDstPort.default_size_bits(), Some(16));
        assert_eq!(FieldId::UdpLen.default_size_bits(), Some(16));
        assert_eq!(FieldId::UdpCksum.default_size_bits(), Some(16));
        assert_eq!(FieldId::UdpDevPort.default_size_bits(), Some(16));
        assert_eq!(FieldId::UdpAppPort.default_size_bits(), Some(16));
    }

    #[test]
    fn test_variable_length_fields() {
        // COAP.TOKEN has variable length ("TKL"), should return None
        assert_eq!(FieldId::CoapToken.default_size_bits(), None);
    }

    // =========================================================================
    // Display trait tests
    // =========================================================================

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", FieldId::Ipv6Ver), "IPV6.VER");
        assert_eq!(format!("{}", FieldId::UdpSrcPort), "UDP.SRC_PORT");
    }

    // =========================================================================
    // Serialization/Deserialization tests
    // =========================================================================

    #[test]
    fn test_serialize() {
        let field = FieldId::Ipv6Ver;
        let json = serde_json::to_string(&field).unwrap();
        assert_eq!(json, "\"IPV6.VER\"");
    }

    #[test]
    fn test_deserialize() {
        let json = "\"UDP.SRC_PORT\"";
        let field: FieldId = serde_json::from_str(json).unwrap();
        assert_eq!(field, FieldId::UdpSrcPort);
    }

    #[test]
    fn test_deserialize_unknown_fails() {
        let json = "\"UNKNOWN.FIELD\"";
        let result: Result<FieldId, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_serialization() {
        let fields = vec![
            FieldId::Ipv4Ver,
            FieldId::Ipv6HopLmt,
            FieldId::UdpCksum,
        ];
        
        for field in fields {
            let json = serde_json::to_string(&field).unwrap();
            let deserialized: FieldId = serde_json::from_str(&json).unwrap();
            assert_eq!(field, deserialized);
        }
    }

    // =========================================================================
    // Hash and equality tests
    // =========================================================================

    #[test]
    fn test_equality() {
        assert_eq!(FieldId::Ipv6Ver, FieldId::Ipv6Ver);
        assert_ne!(FieldId::Ipv6Ver, FieldId::Ipv4Ver);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashMap;
        
        let mut map = HashMap::new();
        map.insert(FieldId::Ipv6Ver, "version");
        map.insert(FieldId::UdpSrcPort, "port");
        
        assert_eq!(map.get(&FieldId::Ipv6Ver), Some(&"version"));
        assert_eq!(map.get(&FieldId::UdpSrcPort), Some(&"port"));
        assert_eq!(map.get(&FieldId::Ipv4Ver), None);
    }
}
