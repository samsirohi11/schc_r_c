//! Field identifier enum for compile-time type safety and performance.
//!
//! Using an enum instead of strings provides:
//! - Zero-cost comparisons (enum variants vs string comparison)
//! - Compile-time validation of field names
//! - No heap allocation for field identifiers

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Unique identifier for packet header fields across all supported protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    // ===== IPv4 Fields =====
    Ipv4Ver,
    Ipv4Ihl,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4Len,
    Ipv4Id,
    Ipv4Flags,
    Ipv4FragOff,
    Ipv4Ttl,
    Ipv4Proto,
    Ipv4Chksum,
    Ipv4Src,
    Ipv4Dst,

    // ===== IPv6 Fields =====
    Ipv6Ver,
    Ipv6Tc,
    Ipv6Fl,
    Ipv6Len,
    Ipv6Nxt,
    Ipv6HopLmt,
    Ipv6Src,
    Ipv6Dst,
    Ipv6SrcPrefix,
    Ipv6SrcIid,
    Ipv6DstPrefix,
    Ipv6DstIid,
    Ipv6DevPrefix,
    Ipv6DevIid,
    Ipv6AppPrefix,
    Ipv6AppIid,

    // ===== UDP Fields =====
    UdpSrcPort,
    UdpDstPort,
    UdpLen,
    UdpCksum,
    UdpDevPort,
    UdpAppPort,

    // ===== QUIC Fields =====
    /// QUIC first byte (8 bits): Contains header form (bit 0) + type-specific bits
    QuicFirstByte,
    /// QUIC version field (32 bits, only present in long header where first bit = 1)
    QuicVersion,
}

impl FieldId {
    /// Returns the canonical string representation used in JSON rules.
    pub fn as_str(&self) -> &'static str {
        match self {
            // IPv4
            FieldId::Ipv4Ver => "IPV4.VER",
            FieldId::Ipv4Ihl => "IPV4.IHL",
            FieldId::Ipv4Dscp => "IPV4.DSCP",
            FieldId::Ipv4Ecn => "IPV4.ECN",
            FieldId::Ipv4Len => "IPV4.LEN",
            FieldId::Ipv4Id => "IPV4.ID",
            FieldId::Ipv4Flags => "IPV4.FLAGS",
            FieldId::Ipv4FragOff => "IPV4.FRAG_OFF",
            FieldId::Ipv4Ttl => "IPV4.TTL",
            FieldId::Ipv4Proto => "IPV4.PROTO",
            FieldId::Ipv4Chksum => "IPV4.CHKSUM",
            FieldId::Ipv4Src => "IPV4.SRC",
            FieldId::Ipv4Dst => "IPV4.DST",
            // IPv6
            FieldId::Ipv6Ver => "IPV6.VER",
            FieldId::Ipv6Tc => "IPV6.TC",
            FieldId::Ipv6Fl => "IPV6.FL",
            FieldId::Ipv6Len => "IPV6.LEN",
            FieldId::Ipv6Nxt => "IPV6.NXT",
            FieldId::Ipv6HopLmt => "IPV6.HOP_LMT",
            FieldId::Ipv6Src => "IPV6.SRC",
            FieldId::Ipv6Dst => "IPV6.DST",
            FieldId::Ipv6SrcPrefix => "IPV6.SRC_PREFIX",
            FieldId::Ipv6SrcIid => "IPV6.SRC_IID",
            FieldId::Ipv6DstPrefix => "IPV6.DST_PREFIX",
            FieldId::Ipv6DstIid => "IPV6.DST_IID",
            FieldId::Ipv6DevPrefix => "IPV6.DEV_PREFIX",
            FieldId::Ipv6DevIid => "IPV6.DEV_IID",
            FieldId::Ipv6AppPrefix => "IPV6.APP_PREFIX",
            FieldId::Ipv6AppIid => "IPV6.APP_IID",
            // UDP
            FieldId::UdpSrcPort => "UDP.SRC_PORT",
            FieldId::UdpDstPort => "UDP.DST_PORT",
            FieldId::UdpLen => "UDP.LEN",
            FieldId::UdpCksum => "UDP.CKSUM",
            FieldId::UdpDevPort => "UDP.DEV_PORT",
            FieldId::UdpAppPort => "UDP.APP_PORT",
            // QUIC
            FieldId::QuicFirstByte => "QUIC.FIRST_BYTE",
            FieldId::QuicVersion => "QUIC.VERSION",
        }
    }

    /// Returns default field size in bits (for known fixed-size fields).
    pub fn default_size_bits(&self) -> Option<u16> {
        match self {
            // IPv4
            FieldId::Ipv4Ver => Some(4),
            FieldId::Ipv4Ihl => Some(4),
            FieldId::Ipv4Dscp => Some(6),
            FieldId::Ipv4Ecn => Some(2),
            FieldId::Ipv4Len => Some(16),
            FieldId::Ipv4Id => Some(16),
            FieldId::Ipv4Flags => Some(3),
            FieldId::Ipv4FragOff => Some(13),
            FieldId::Ipv4Ttl => Some(8),
            FieldId::Ipv4Proto => Some(8),
            FieldId::Ipv4Chksum => Some(16),
            FieldId::Ipv4Src => Some(32),
            FieldId::Ipv4Dst => Some(32),
            // IPv6
            FieldId::Ipv6Ver => Some(4),
            FieldId::Ipv6Tc => Some(8),
            FieldId::Ipv6Fl => Some(20),
            FieldId::Ipv6Len => Some(16),
            FieldId::Ipv6Nxt => Some(8),
            FieldId::Ipv6HopLmt => Some(8),
            FieldId::Ipv6Src | FieldId::Ipv6Dst => Some(128),
            FieldId::Ipv6SrcPrefix | FieldId::Ipv6DstPrefix |
            FieldId::Ipv6DevPrefix | FieldId::Ipv6AppPrefix => Some(64),
            FieldId::Ipv6SrcIid | FieldId::Ipv6DstIid |
            FieldId::Ipv6DevIid | FieldId::Ipv6AppIid => Some(64),
            // UDP
            FieldId::UdpSrcPort | FieldId::UdpDstPort |
            FieldId::UdpDevPort | FieldId::UdpAppPort => Some(16),
            FieldId::UdpLen => Some(16),
            FieldId::UdpCksum => Some(16),
            // QUIC
            FieldId::QuicFirstByte => Some(8),
            FieldId::QuicVersion => Some(32),
        }
    }
}

impl fmt::Display for FieldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ParseFieldIdError(pub String);

impl fmt::Display for ParseFieldIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown field ID: {}", self.0)
    }
}

impl std::error::Error for ParseFieldIdError {}

impl FromStr for FieldId {
    type Err = ParseFieldIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // IPv4
            "IPV4.VER" => Ok(FieldId::Ipv4Ver),
            "IPV4.IHL" => Ok(FieldId::Ipv4Ihl),
            "IPV4.DSCP" => Ok(FieldId::Ipv4Dscp),
            "IPV4.ECN" => Ok(FieldId::Ipv4Ecn),
            "IPV4.LEN" => Ok(FieldId::Ipv4Len),
            "IPV4.ID" => Ok(FieldId::Ipv4Id),
            "IPV4.FLAGS" => Ok(FieldId::Ipv4Flags),
            "IPV4.FRAG_OFF" => Ok(FieldId::Ipv4FragOff),
            "IPV4.TTL" => Ok(FieldId::Ipv4Ttl),
            "IPV4.PROTO" => Ok(FieldId::Ipv4Proto),
            "IPV4.CHKSUM" => Ok(FieldId::Ipv4Chksum),
            "IPV4.SRC" => Ok(FieldId::Ipv4Src),
            "IPV4.DST" => Ok(FieldId::Ipv4Dst),
            // IPv6
            "IPV6.VER" => Ok(FieldId::Ipv6Ver),
            "IPV6.TC" => Ok(FieldId::Ipv6Tc),
            "IPV6.FL" => Ok(FieldId::Ipv6Fl),
            "IPV6.LEN" => Ok(FieldId::Ipv6Len),
            "IPV6.NXT" => Ok(FieldId::Ipv6Nxt),
            "IPV6.HOP_LMT" => Ok(FieldId::Ipv6HopLmt),
            "IPV6.SRC" => Ok(FieldId::Ipv6Src),
            "IPV6.DST" => Ok(FieldId::Ipv6Dst),
            "IPV6.SRC_PREFIX" => Ok(FieldId::Ipv6SrcPrefix),
            "IPV6.SRC_IID" => Ok(FieldId::Ipv6SrcIid),
            "IPV6.DST_PREFIX" => Ok(FieldId::Ipv6DstPrefix),
            "IPV6.DST_IID" => Ok(FieldId::Ipv6DstIid),
            "IPV6.DEV_PREFIX" => Ok(FieldId::Ipv6DevPrefix),
            "IPV6.DEV_IID" => Ok(FieldId::Ipv6DevIid),
            "IPV6.APP_PREFIX" => Ok(FieldId::Ipv6AppPrefix),
            "IPV6.APP_IID" => Ok(FieldId::Ipv6AppIid),
            // UDP
            "UDP.SRC_PORT" => Ok(FieldId::UdpSrcPort),
            "UDP.DST_PORT" => Ok(FieldId::UdpDstPort),
            "UDP.LEN" => Ok(FieldId::UdpLen),
            "UDP.CKSUM" => Ok(FieldId::UdpCksum),
            "UDP.DEV_PORT" => Ok(FieldId::UdpDevPort),
            "UDP.APP_PORT" => Ok(FieldId::UdpAppPort),
            // QUIC
            "QUIC.FIRST_BYTE" => Ok(FieldId::QuicFirstByte),
            "QUIC.VERSION" => Ok(FieldId::QuicVersion),
            _ => Err(ParseFieldIdError(s.to_string())),
        }
    }
}

impl Serialize for FieldId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FieldId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FieldId::from_str(&s).map_err(serde::de::Error::custom)
    }
}

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
        assert_eq!(FieldId::Ipv6Src.as_str(), "IPV6.SRC");
        assert_eq!(FieldId::Ipv6Dst.as_str(), "IPV6.DST");
        assert_eq!(FieldId::Ipv6SrcPrefix.as_str(), "IPV6.SRC_PREFIX");
        assert_eq!(FieldId::Ipv6SrcIid.as_str(), "IPV6.SRC_IID");
        assert_eq!(FieldId::Ipv6DstPrefix.as_str(), "IPV6.DST_PREFIX");
        assert_eq!(FieldId::Ipv6DstIid.as_str(), "IPV6.DST_IID");
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
        assert_eq!(FieldId::from_str("IPV6.SRC_PREFIX").unwrap(), FieldId::Ipv6SrcPrefix);
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
        assert_eq!(FieldId::Ipv6Src.default_size_bits(), Some(128));
        assert_eq!(FieldId::Ipv6Dst.default_size_bits(), Some(128));
        assert_eq!(FieldId::Ipv6SrcPrefix.default_size_bits(), Some(64));
        assert_eq!(FieldId::Ipv6SrcIid.default_size_bits(), Some(64));
        assert_eq!(FieldId::Ipv6DstPrefix.default_size_bits(), Some(64));
        assert_eq!(FieldId::Ipv6DstIid.default_size_bits(), Some(64));
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
