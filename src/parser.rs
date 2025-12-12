//! Streaming Packet Parser
//!
//! On-demand field extraction from raw packets. Fields are parsed lazily
//! during tree traversal to enable early pruning when mismatches are detected.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;

use crate::error::{Result, SchcError};
use crate::field_id::FieldId;

// =============================================================================
// Direction
// =============================================================================

/// Packet direction for directional field resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Up,   // DEV -> APP
    Down, // APP -> DEV
}

// =============================================================================
// Field Values
// =============================================================================

/// Parsed field value from a packet
#[derive(Debug, Clone)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Bytes(Vec<u8>),
}

impl FieldValue {
    /// Convert field value to string representation
    pub fn as_string(&self) -> String {
        match self {
            FieldValue::U8(v) => v.to_string(),
            FieldValue::U16(v) => v.to_string(),
            FieldValue::U32(v) => v.to_string(),
            FieldValue::U64(v) => v.to_string(),
            FieldValue::Ipv4(v) => v.to_string(),
            FieldValue::Ipv6(v) => v.to_string(),
            FieldValue::Bytes(v) => hex::encode(v),
        }
    }
    
    /// Get size of this field value in bits
    pub fn size_bits(&self) -> u16 {
        match self {
            FieldValue::U8(_) => 8,
            FieldValue::U16(_) => 16,
            FieldValue::U32(_) => 32,
            FieldValue::U64(_) => 64,
            FieldValue::Ipv4(_) => 32,
            FieldValue::Ipv6(_) => 128,
            FieldValue::Bytes(b) => (b.len() * 8) as u16,
        }
    }
}

// =============================================================================
// Protocol Layer Detection
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ProtocolLayer {
    Ipv4,
    Ipv6,
    Unknown,
}

// =============================================================================
// Streaming Parser
// =============================================================================

/// Lazy packet parser that extracts fields on-demand during tree traversal
pub struct StreamingParser<'a> {
    raw: &'a [u8],
    ip_start: usize,
    layer: ProtocolLayer,
    next_protocol: Option<u8>,
    direction: Direction,
    pub(crate) parsed_fields: HashMap<FieldId, FieldValue>,
}

impl<'a> StreamingParser<'a> {
    /// Create a new streaming parser for a raw packet
    pub fn new(raw: &'a [u8], direction: Direction) -> Result<Self> {
        if raw.is_empty() {
            return Err(SchcError::PacketParse("Empty packet".to_string()));
        }

        let ip_start = if raw.len() > 14 {
            if let Some(_eth) = EthernetPacket::new(raw) {
                14
            } else {
                14 // Assume ethernet
            }
        } else {
            0
        };

        let layer = if ip_start < raw.len() {
            let version = (raw[ip_start] >> 4) & 0x0F;
            match version {
                4 => ProtocolLayer::Ipv4,
                6 => ProtocolLayer::Ipv6,
                _ => ProtocolLayer::Unknown,
            }
        } else {
            ProtocolLayer::Unknown
        };

        Ok(Self {
            raw,
            ip_start,
            layer,
            next_protocol: None,
            direction,
            parsed_fields: HashMap::new(),
        })
    }

    /// Get the IP start offset (for external use in display functions)
    pub fn ip_start(&self) -> usize {
        self.ip_start
    }

    /// Get the raw packet data
    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    /// Parse a field and cache the result
    pub fn parse_field(&mut self, fid: FieldId) -> Result<Option<&FieldValue>> {
        if self.parsed_fields.contains_key(&fid) {
            return Ok(self.parsed_fields.get(&fid));
        }

        if let Some(value) = self.extract_field(fid)? {
            self.parsed_fields.insert(fid, value);
            Ok(self.parsed_fields.get(&fid))
        } else {
            Ok(None)
        }
    }

    /// Check if this is a source field based on direction
    fn get_directional_source(&self, is_dev: bool) -> bool {
        match (is_dev, self.direction) {
            (true, Direction::Up) | (false, Direction::Down) => true,
            (true, Direction::Down) | (false, Direction::Up) => false,
        }
    }

    /// Extract a field value from the packet
    fn extract_field(&mut self, fid: FieldId) -> Result<Option<FieldValue>> {
        let ip_data = &self.raw[self.ip_start..];

        match fid {
            // IPv4 Fields
            FieldId::Ipv4Ver | FieldId::Ipv4Ihl | FieldId::Ipv4Dscp | FieldId::Ipv4Ecn |
            FieldId::Ipv4Len | FieldId::Ipv4Id | FieldId::Ipv4Flags | FieldId::Ipv4FragOff |
            FieldId::Ipv4Ttl | FieldId::Ipv4Proto | FieldId::Ipv4Chksum | 
            FieldId::Ipv4Src | FieldId::Ipv4Dst => {
                if self.layer != ProtocolLayer::Ipv4 {
                    return Ok(None);
                }
                self.extract_ipv4_field(ip_data, fid)
            }

            // IPv6 Fields
            FieldId::Ipv6Ver | FieldId::Ipv6Tc | FieldId::Ipv6Fl | FieldId::Ipv6Len |
            FieldId::Ipv6Nxt | FieldId::Ipv6HopLmt | FieldId::Ipv6Src | FieldId::Ipv6Dst |
            FieldId::Ipv6SrcPrefix | FieldId::Ipv6SrcIid | FieldId::Ipv6DstPrefix | FieldId::Ipv6DstIid => {
                if self.layer != ProtocolLayer::Ipv6 {
                    return Ok(None);
                }
                self.extract_ipv6_field(ip_data, fid)
            }

            // Direction-based IPv6 fields
            FieldId::Ipv6DevPrefix | FieldId::Ipv6AppPrefix => {
                let is_dev = matches!(fid, FieldId::Ipv6DevPrefix);
                let source_fid = if self.get_directional_source(is_dev) {
                    FieldId::Ipv6SrcPrefix
                } else {
                    FieldId::Ipv6DstPrefix
                };
                self.extract_field(source_fid)
            }
            FieldId::Ipv6DevIid | FieldId::Ipv6AppIid => {
                let is_dev = matches!(fid, FieldId::Ipv6DevIid);
                let source_fid = if self.get_directional_source(is_dev) {
                    FieldId::Ipv6SrcIid
                } else {
                    FieldId::Ipv6DstIid
                };
                self.extract_field(source_fid)
            }

            // UDP Fields
            FieldId::UdpSrcPort | FieldId::UdpDstPort | FieldId::UdpLen | FieldId::UdpCksum => {
                self.extract_udp_field(fid)
            }

            // Direction-based UDP ports
            FieldId::UdpDevPort | FieldId::UdpAppPort => {
                let is_dev = matches!(fid, FieldId::UdpDevPort);
                let source_fid = if self.get_directional_source(is_dev) {
                    FieldId::UdpSrcPort
                } else {
                    FieldId::UdpDstPort
                };
                self.extract_field(source_fid)
            }

            // QUIC Fields
            FieldId::QuicFirstByte | FieldId::QuicVersion => {
                self.extract_quic_field(fid)
            }
        }
    }

    fn extract_ipv4_field(&mut self, data: &[u8], fid: FieldId) -> Result<Option<FieldValue>> {
        let ipv4 = match Ipv4Packet::new(data) {
            Some(p) => p,
            None => return Ok(None),
        };

        if self.next_protocol.is_none() {
            self.next_protocol = Some(ipv4.get_next_level_protocol().0);
        }

        let value = match fid {
            FieldId::Ipv4Ver => FieldValue::U8(ipv4.get_version()),
            FieldId::Ipv4Ihl => FieldValue::U8(ipv4.get_header_length()),
            FieldId::Ipv4Dscp => FieldValue::U8(ipv4.get_dscp()),
            FieldId::Ipv4Ecn => FieldValue::U8(ipv4.get_ecn()),
            FieldId::Ipv4Len => FieldValue::U16(ipv4.get_total_length()),
            FieldId::Ipv4Id => FieldValue::U16(ipv4.get_identification()),
            FieldId::Ipv4Flags => FieldValue::U8(ipv4.get_flags()),
            FieldId::Ipv4FragOff => FieldValue::U16(ipv4.get_fragment_offset()),
            FieldId::Ipv4Ttl => FieldValue::U8(ipv4.get_ttl()),
            FieldId::Ipv4Proto => FieldValue::U8(ipv4.get_next_level_protocol().0),
            FieldId::Ipv4Chksum => FieldValue::U16(ipv4.get_checksum()),
            FieldId::Ipv4Src => FieldValue::Ipv4(ipv4.get_source()),
            FieldId::Ipv4Dst => FieldValue::Ipv4(ipv4.get_destination()),
            _ => return Ok(None),
        };

        Ok(Some(value))
    }

    fn extract_ipv6_field(&mut self, data: &[u8], fid: FieldId) -> Result<Option<FieldValue>> {
        let ipv6 = match Ipv6Packet::new(data) {
            Some(p) => p,
            None => return Ok(None),
        };

        if self.next_protocol.is_none() {
            self.next_protocol = Some(ipv6.get_next_header().0);
        }

        let value = match fid {
            FieldId::Ipv6Ver => FieldValue::U8(ipv6.get_version()),
            FieldId::Ipv6Tc => FieldValue::U8(ipv6.get_traffic_class()),
            FieldId::Ipv6Fl => FieldValue::U32(ipv6.get_flow_label()),
            FieldId::Ipv6Len => FieldValue::U16(ipv6.get_payload_length()),
            FieldId::Ipv6Nxt => FieldValue::U8(ipv6.get_next_header().0),
            FieldId::Ipv6HopLmt => FieldValue::U8(ipv6.get_hop_limit()),
            FieldId::Ipv6Src => FieldValue::Ipv6(ipv6.get_source()),
            FieldId::Ipv6Dst => FieldValue::Ipv6(ipv6.get_destination()),
            FieldId::Ipv6SrcPrefix => {
                let src_bytes = ipv6.get_source().octets();
                FieldValue::Bytes(src_bytes[0..8].to_vec())
            }
            FieldId::Ipv6SrcIid => {
                let src_bytes = ipv6.get_source().octets();
                let iid = u64::from_be_bytes([
                    src_bytes[8], src_bytes[9], src_bytes[10], src_bytes[11],
                    src_bytes[12], src_bytes[13], src_bytes[14], src_bytes[15],
                ]);
                FieldValue::U64(iid)
            }
            FieldId::Ipv6DstPrefix => {
                let dst_bytes = ipv6.get_destination().octets();
                FieldValue::Bytes(dst_bytes[0..8].to_vec())
            }
            FieldId::Ipv6DstIid => {
                let dst_bytes = ipv6.get_destination().octets();
                let iid = u64::from_be_bytes([
                    dst_bytes[8], dst_bytes[9], dst_bytes[10], dst_bytes[11],
                    dst_bytes[12], dst_bytes[13], dst_bytes[14], dst_bytes[15],
                ]);
                FieldValue::U64(iid)
            }
            _ => return Ok(None),
        };

        Ok(Some(value))
    }

    fn extract_udp_field(&mut self, fid: FieldId) -> Result<Option<FieldValue>> {
        let udp_start = self.get_udp_start()?;
        
        if udp_start >= self.raw.len() {
            return Ok(None);
        }

        let udp = match UdpPacket::new(&self.raw[udp_start..]) {
            Some(p) => p,
            None => return Ok(None),
        };

        let value = match fid {
            FieldId::UdpSrcPort => FieldValue::U16(udp.get_source()),
            FieldId::UdpDstPort => FieldValue::U16(udp.get_destination()),
            FieldId::UdpLen => FieldValue::U16(udp.get_length()),
            FieldId::UdpCksum => FieldValue::U16(udp.get_checksum()),
            _ => return Ok(None),
        };

        Ok(Some(value))
    }

    fn get_udp_start(&mut self) -> Result<usize> {
        if self.next_protocol.is_none() {
            let ip_data = &self.raw[self.ip_start..];
            match self.layer {
                ProtocolLayer::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                        self.next_protocol = Some(ipv4.get_next_level_protocol().0);
                    }
                }
                ProtocolLayer::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ip_data) {
                        self.next_protocol = Some(ipv6.get_next_header().0);
                    }
                }
                _ => {}
            }
        }

        if self.next_protocol != Some(17) {
            return Err(SchcError::PacketParse("Not a UDP packet".to_string()));
        }

        let udp_start = match self.layer {
            ProtocolLayer::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(&self.raw[self.ip_start..]) {
                    self.ip_start + (ipv4.get_header_length() as usize) * 4
                } else {
                    return Err(SchcError::PacketParse("Invalid IPv4 packet".to_string()));
                }
            }
            ProtocolLayer::Ipv6 => self.ip_start + 40,
            _ => return Err(SchcError::PacketParse("Unknown IP layer".to_string())),
        };

        Ok(udp_start)
    }

    /// Get the total header length (IP + transport) in bytes
    /// Returns the header size excluding the ethernet header
    pub fn header_length(&mut self) -> Result<usize> {
        let udp_start = self.get_udp_start()?;
        Ok(udp_start + 8 - 14) // Subtract ethernet header (14 bytes) for actual IP+UDP header
    }

    /// Get the QUIC header start offset (after UDP header)
    /// Returns None if UDP ports don't indicate QUIC traffic
    fn get_quic_start(&mut self) -> Result<Option<usize>> {
        let udp_start = self.get_udp_start()?;
        
        // Check if this is QUIC traffic by examining UDP ports
        // Reuse already-parsed UDP port fields instead of reading raw bytes again
        // QUIC typically uses port 443 (HTTPS over QUIC) or 4433 (alternate QUIC port)
        
        // Parse UDP source and destination ports if not already cached
        let src_port = if let Ok(Some(val)) = self.parse_field(FieldId::UdpSrcPort) {
            match val {
                FieldValue::U16(p) => *p,
                _ => return Ok(None),
            }
        } else {
            return Ok(None);
        };

        let dst_port = if let Ok(Some(val)) = self.parse_field(FieldId::UdpDstPort) {
            match val {
                FieldValue::U16(p) => *p,
                _ => return Ok(None),
            }
        } else {
            return Ok(None);
        };
        
        // Only parse QUIC if either port is 443 or 4433
        if src_port != 443 && src_port != 4433 && dst_port != 443 && dst_port != 4433 {
            return Ok(None);
        }
        
        Ok(Some(udp_start + 8)) // UDP header is 8 bytes
    }

    /// Extract QUIC header fields
    /// 
    /// QUIC is only parsed when UDP port is 443 or 4433.
    /// 
    /// QUIC header structure (RFC 9000):
    /// - Long Header (first bit = 1):
    ///   - First byte (8 bits): Header Form (1) + Fixed Bit + Long Packet Type + Type-Specific Bits
    ///   - Version (32 bits)
    ///   - ... (rest not parsed - DCID, SCID, etc.)
    /// 
    /// - Short Header (first bit = 0):
    ///   - First byte (8 bits): Header Form (0) + Fixed Bit + Spin Bit + Reserved + Key Phase + PN Length
    ///   - ... (no version field in short header)
    /// 
    /// Note: The first byte should be kept as-is (value-sent) in compression.
    /// Only the version field is eligible for compression (not-sent) in long headers.
     
    fn extract_quic_field(&mut self, fid: FieldId) -> Result<Option<FieldValue>> {
        let quic_start = match self.get_quic_start() {
            Ok(Some(start)) => start,
            Ok(None) => return Ok(None), // Not a QUIC packet (wrong ports)
            Err(_) => return Ok(None), // Not a UDP packet
        };

        if quic_start >= self.raw.len() {
            return Ok(None);
        }

        let quic_data = &self.raw[quic_start..];
        if quic_data.is_empty() {
            return Ok(None);
        }

        // First byte contains the header form bit (MSB)
        let first_byte = quic_data[0];
        let header_form = (first_byte >> 7) & 0x01; // Most significant bit: 1 = long, 0 = short
        let is_long_header = header_form == 1;

        match fid {
            FieldId::QuicFirstByte => {
                Ok(Some(FieldValue::U8(first_byte)))
            }
            FieldId::QuicVersion => {
                if !is_long_header {
                    // Short header has no version field
                    return Ok(None);
                }

                // Version field starts at byte 1 and is 4 bytes
                if quic_data.len() < 5 {
                    return Ok(None);
                }

                let version = u32::from_be_bytes([
                    quic_data[1],
                    quic_data[2],
                    quic_data[3],
                    quic_data[4],
                ]);
                Ok(Some(FieldValue::U32(version)))
            }
            _ => Ok(None),
        }
    }
}

// =============================================================================
// Helper Functions for Parsing Packets
// =============================================================================

/// Parse and return all packet fields for debugging
pub fn parse_packet_fields(raw_packet: &[u8], direction: Direction) -> Result<Vec<(FieldId, String)>> {
    let mut parser = StreamingParser::new(raw_packet, direction)?;
    let mut fields = Vec::new();

    // Try all common fields based on detected layer
    let ip_version = if parser.ip_start() < raw_packet.len() {
        (raw_packet[parser.ip_start()] >> 4) & 0x0F
    } else {
        0
    };

    let field_ids: Vec<FieldId> = if ip_version == 6 {
        vec![
            FieldId::Ipv6Ver, FieldId::Ipv6Tc, FieldId::Ipv6Fl,
            FieldId::Ipv6Len, FieldId::Ipv6Nxt, FieldId::Ipv6HopLmt,
            FieldId::Ipv6SrcPrefix, FieldId::Ipv6SrcIid,
            FieldId::Ipv6DstPrefix, FieldId::Ipv6DstIid,
            FieldId::UdpSrcPort, FieldId::UdpDstPort, FieldId::UdpLen, FieldId::UdpCksum,
            // QUIC fields (only attempt if we have a UDP packet with QUIC ports)
            FieldId::QuicFirstByte, FieldId::QuicVersion,
        ]
    } else if ip_version == 4 {
        vec![
            FieldId::Ipv4Ver, FieldId::Ipv4Ihl, FieldId::Ipv4Dscp, FieldId::Ipv4Ecn,
            FieldId::Ipv4Len, FieldId::Ipv4Id, FieldId::Ipv4Flags, FieldId::Ipv4FragOff,
            FieldId::Ipv4Ttl, FieldId::Ipv4Proto, FieldId::Ipv4Chksum,
            FieldId::Ipv4Src, FieldId::Ipv4Dst,
            FieldId::UdpSrcPort, FieldId::UdpDstPort, FieldId::UdpLen, FieldId::UdpCksum,
            // QUIC fields (only attempt if we have a UDP packet with QUIC ports)
            FieldId::QuicFirstByte, FieldId::QuicVersion,
        ]
    } else {
        vec![]
    };

    for fid in field_ids {
        if let Ok(Some(val)) = parser.parse_field(fid) {
            fields.push((fid, val.as_string()));
        }
    }

    Ok(fields)
}

/// Display packet fields in a formatted way
pub fn display_packet_fields(raw_packet: &[u8], direction: Direction) {
    match parse_packet_fields(raw_packet, direction) {
        Ok(fields) => {
            println!("--- Packet Fields ---");
            for (fid, value) in &fields {
                let size_bits = fid.default_size_bits().unwrap_or(0);
                println!("  {} ({}b): {}", fid, size_bits, value);
            }
            println!();
        }
        Err(e) => {
            eprintln!("Failed to parse packet fields: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // =========================================================================
    // FieldValue tests
    // =========================================================================

    #[test]
    fn test_field_value_as_string() {
        assert_eq!(FieldValue::U8(42).as_string(), "42");
        assert_eq!(FieldValue::U16(1234).as_string(), "1234");
        assert_eq!(FieldValue::U32(0xDEADBEEF).as_string(), "3735928559");
        assert_eq!(FieldValue::U64(0x123456789ABCDEF0).as_string(), "1311768467463790320");
        
        let ipv4: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(FieldValue::Ipv4(ipv4).as_string(), "192.168.1.1");
        
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(FieldValue::Ipv6(ipv6).as_string(), "2001:db8::1");
        
        assert_eq!(FieldValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]).as_string(), "deadbeef");
    }

    #[test]
    fn test_field_value_size_bits() {
        assert_eq!(FieldValue::U8(0).size_bits(), 8);
        assert_eq!(FieldValue::U16(0).size_bits(), 16);
        assert_eq!(FieldValue::U32(0).size_bits(), 32);
        assert_eq!(FieldValue::U64(0).size_bits(), 64);
        assert_eq!(FieldValue::Ipv4("0.0.0.0".parse().unwrap()).size_bits(), 32);
        assert_eq!(FieldValue::Ipv6("::".parse().unwrap()).size_bits(), 128);
        assert_eq!(FieldValue::Bytes(vec![0; 8]).size_bits(), 64);
        assert_eq!(FieldValue::Bytes(vec![]).size_bits(), 0);
    }

    // =========================================================================
    // StreamingParser creation tests
    // =========================================================================

    #[test]
    fn test_parser_empty_packet() {
        let result = StreamingParser::new(&[], Direction::Up);
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_short_packet() {
        // Packet shorter than ethernet header
        let short_packet = vec![0x45, 0x00, 0x00, 0x14];
        let parser = StreamingParser::new(&short_packet, Direction::Up).unwrap();
        assert_eq!(parser.ip_start(), 0); // No ethernet header assumed
    }

    // =========================================================================
    // IPv4 packet parsing tests
    // =========================================================================

    /// Creates a minimal IPv4/UDP packet with ethernet header
    fn create_ipv4_udp_packet() -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
            0x08, 0x00,                          // EtherType (IPv4)
        ];
        
        // IPv4 header (20 bytes, no options)
        let ipv4_header = vec![
            0x45,       // Version (4) + IHL (5)
            0x00,       // DSCP + ECN
            0x00, 0x1C, // Total length (28 = 20 + 8)
            0x12, 0x34, // Identification
            0x40, 0x00, // Flags (Don't Fragment) + Fragment Offset
            0x40,       // TTL (64)
            0x11,       // Protocol (UDP = 17)
            0x00, 0x00, // Checksum (0 for test)
            0xC0, 0xA8, 0x01, 0x64, // Src IP: 192.168.1.100
            0xC0, 0xA8, 0x01, 0x01, // Dst IP: 192.168.1.1
        ];
        packet.extend(ipv4_header);
        
        // UDP header (8 bytes)
        let udp_header = vec![
            0x13, 0xC4, // Src Port: 5060
            0x00, 0x50, // Dst Port: 80
            0x00, 0x08, // Length: 8 (header only)
            0x00, 0x00, // Checksum
        ];
        packet.extend(udp_header);
        
        packet
    }

    #[test]
    fn test_parse_ipv4_version() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let version = parser.parse_field(FieldId::Ipv4Ver).unwrap().unwrap();
        match version {
            FieldValue::U8(v) => assert_eq!(*v, 4),
            _ => panic!("Expected U8 for IPv4 version"),
        }
    }

    #[test]
    fn test_parse_ipv4_ttl() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let ttl = parser.parse_field(FieldId::Ipv4Ttl).unwrap().unwrap();
        match ttl {
            FieldValue::U8(v) => assert_eq!(*v, 64),
            _ => panic!("Expected U8 for TTL"),
        }
    }

    #[test]
    fn test_parse_ipv4_addresses() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let src = parser.parse_field(FieldId::Ipv4Src).unwrap().unwrap();
        match src {
            FieldValue::Ipv4(addr) => assert_eq!(*addr, "192.168.1.100".parse::<Ipv4Addr>().unwrap()),
            _ => panic!("Expected Ipv4 for source address"),
        }
        
        let dst = parser.parse_field(FieldId::Ipv4Dst).unwrap().unwrap();
        match dst {
            FieldValue::Ipv4(addr) => assert_eq!(*addr, "192.168.1.1".parse::<Ipv4Addr>().unwrap()),
            _ => panic!("Expected Ipv4 for destination address"),
        }
    }

    #[test]
    fn test_parse_udp_ports_ipv4() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let src_port = parser.parse_field(FieldId::UdpSrcPort).unwrap().unwrap();
        match src_port {
            FieldValue::U16(v) => assert_eq!(*v, 5060),
            _ => panic!("Expected U16 for UDP source port"),
        }
        
        let dst_port = parser.parse_field(FieldId::UdpDstPort).unwrap().unwrap();
        match dst_port {
            FieldValue::U16(v) => assert_eq!(*v, 80),
            _ => panic!("Expected U16 for UDP destination port"),
        }
    }

    // =========================================================================
    // IPv6 packet parsing tests
    // =========================================================================

    /// Creates a minimal IPv6/UDP packet with ethernet header
    fn create_ipv6_udp_packet() -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
            0x86, 0xDD,                          // EtherType (IPv6)
        ];
        
        // IPv6 header (40 bytes)
        let ipv6_header = vec![
            0x60, 0x12, 0x34, 0x56, // Version (6) + TC (0x01) + Flow Label (0x23456)
            0x00, 0x08,             // Payload Length (8 bytes = UDP header)
            0x11,                   // Next Header (UDP = 17)
            0x40,                   // Hop Limit (64)
            // Source: 2001:db8:1234:5678:9abc:def0:1234:5678
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            // Destination: 2001:db8:abcd:ef01:2345:6789:abcd:ef01
            0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ];
        packet.extend(ipv6_header);
        
        // UDP header (8 bytes)
        let udp_header = vec![
            0x1F, 0x90, // Src Port: 8080
            0x01, 0xBB, // Dst Port: 443
            0x00, 0x08, // Length: 8 (header only)
            0x00, 0x00, // Checksum
        ];
        packet.extend(udp_header);
        
        packet
    }

    #[test]
    fn test_parse_ipv6_version() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let version = parser.parse_field(FieldId::Ipv6Ver).unwrap().unwrap();
        match version {
            FieldValue::U8(v) => assert_eq!(*v, 6),
            _ => panic!("Expected U8 for IPv6 version"),
        }
    }

    #[test]
    fn test_parse_ipv6_hop_limit() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let hop = parser.parse_field(FieldId::Ipv6HopLmt).unwrap().unwrap();
        match hop {
            FieldValue::U8(v) => assert_eq!(*v, 64),
            _ => panic!("Expected U8 for hop limit"),
        }
    }

    #[test]
    fn test_parse_ipv6_prefix() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let prefix = parser.parse_field(FieldId::Ipv6SrcPrefix).unwrap().unwrap();
        match prefix {
            FieldValue::Bytes(b) => {
                assert_eq!(b.len(), 8);
                assert_eq!(*b, vec![0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78]);
            }
            _ => panic!("Expected Bytes for IPv6 prefix"),
        }
    }

    #[test]
    fn test_parse_ipv6_iid() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let iid = parser.parse_field(FieldId::Ipv6SrcIid).unwrap().unwrap();
        match iid {
            FieldValue::U64(v) => {
                // IID: 9abc:def0:1234:5678
                assert_eq!(*v, 0x9abcdef012345678);
            }
            _ => panic!("Expected U64 for IPv6 IID"),
        }
    }

    #[test]
    fn test_parse_udp_ports_ipv6() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let src_port = parser.parse_field(FieldId::UdpSrcPort).unwrap().unwrap();
        match src_port {
            FieldValue::U16(v) => assert_eq!(*v, 8080),
            _ => panic!("Expected U16 for UDP source port"),
        }
        
        let dst_port = parser.parse_field(FieldId::UdpDstPort).unwrap().unwrap();
        match dst_port {
            FieldValue::U16(v) => assert_eq!(*v, 443),
            _ => panic!("Expected U16 for UDP destination port"),
        }
    }

    // =========================================================================
    // Field caching tests
    // =========================================================================

    #[test]
    fn test_field_caching() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        // First parse
        let _ = parser.parse_field(FieldId::Ipv4Ttl).unwrap();
        assert!(parser.parsed_fields.contains_key(&FieldId::Ipv4Ttl));
        
        // Second parse should use cache
        let ttl = parser.parse_field(FieldId::Ipv4Ttl).unwrap().unwrap();
        match ttl {
            FieldValue::U8(v) => assert_eq!(*v, 64),
            _ => panic!("Expected cached U8 for TTL"),
        }
    }

    // =========================================================================
    // Direction-based field tests
    // =========================================================================

    #[test]
    fn test_directional_udp_ports_up() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        // In UP direction: DEV = source, APP = destination
        let dev_port = parser.parse_field(FieldId::UdpDevPort).unwrap().unwrap();
        match dev_port {
            FieldValue::U16(v) => assert_eq!(*v, 5060), // Source port
            _ => panic!("Expected source port for DEV in UP direction"),
        }
        
        let app_port = parser.parse_field(FieldId::UdpAppPort).unwrap().unwrap();
        match app_port {
            FieldValue::U16(v) => assert_eq!(*v, 80), // Destination port
            _ => panic!("Expected destination port for APP in UP direction"),
        }
    }

    #[test]
    fn test_directional_udp_ports_down() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Down).unwrap();
        
        // In DOWN direction: DEV = destination, APP = source
        let dev_port = parser.parse_field(FieldId::UdpDevPort).unwrap().unwrap();
        match dev_port {
            FieldValue::U16(v) => assert_eq!(*v, 80), // Destination port
            _ => panic!("Expected destination port for DEV in DOWN direction"),
        }
        
        let app_port = parser.parse_field(FieldId::UdpAppPort).unwrap().unwrap();
        match app_port {
            FieldValue::U16(v) => assert_eq!(*v, 5060), // Source port
            _ => panic!("Expected source port for APP in DOWN direction"),
        }
    }

    // =========================================================================
    // Cross-layer field access tests
    // =========================================================================

    #[test]
    fn test_ipv6_field_on_ipv4_packet() {
        let packet = create_ipv4_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        // Should return None, not an error
        let result = parser.parse_field(FieldId::Ipv6Ver).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ipv4_field_on_ipv6_packet() {
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        // Should return None, not an error
        let result = parser.parse_field(FieldId::Ipv4Ver).unwrap();
        assert!(result.is_none());
    }

    // =========================================================================
    // QUIC header parsing tests
    // =========================================================================

    /// Creates an IPv6/UDP/QUIC Long Header packet (port 443, header form = 1)
    fn create_ipv6_quic_long_header_packet() -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
            0x86, 0xDD,                          // EtherType (IPv6)
        ];
        
        // IPv6 header (40 bytes)
        let ipv6_header = vec![
            0x60, 0x00, 0x00, 0x00, // Version (6) + TC + Flow Label
            0x00, 0x15,             // Payload Length (21 bytes = 8 UDP + 13 QUIC)
            0x11,                   // Next Header (UDP = 17)
            0x40,                   // Hop Limit (64)
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        packet.extend(ipv6_header);
        
        // UDP header (8 bytes) - destination port 443 (QUIC)
        let udp_header = vec![
            0x1F, 0x90, // Src Port: 8080
            0x01, 0xBB, // Dst Port: 443 (QUIC)
            0x00, 0x15, // Length: 21 bytes
            0x00, 0x00, // Checksum
        ];
        packet.extend(udp_header);
        
        // QUIC Long Header (first byte + 4 byte version + more)
        // First byte: 1xxxxxxx (header form = 1, long header)
        let quic_header = vec![
            0xC3,                   // Long header: 1100 0011 (form=1, fixed=1, type=00, reserved)
            0x00, 0x00, 0x00, 0x01, // Version: 1 (QUIC version 1)
            0x05,                   // DCID Length: 5
            0x01, 0x02, 0x03, 0x04, 0x05, // DCID
            0x00,                   // SCID Length: 0
        ];
        packet.extend(quic_header);
        
        packet
    }

    /// Creates an IPv6/UDP/QUIC Short Header packet (port 443, header form = 0)
    fn create_ipv6_quic_short_header_packet() -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
            0x86, 0xDD,                          // EtherType (IPv6)
        ];
        
        // IPv6 header (40 bytes)
        let ipv6_header = vec![
            0x60, 0x00, 0x00, 0x00, // Version (6) + TC + Flow Label
            0x00, 0x10,             // Payload Length (16 bytes = 8 UDP + 8 QUIC)
            0x11,                   // Next Header (UDP = 17)
            0x40,                   // Hop Limit (64)
            // Source: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Destination: 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        packet.extend(ipv6_header);
        
        // UDP header (8 bytes) - source port 443 (QUIC)
        let udp_header = vec![
            0x01, 0xBB, // Src Port: 443 (QUIC)
            0x1F, 0x90, // Dst Port: 8080
            0x00, 0x10, // Length: 16 bytes
            0x00, 0x00, // Checksum
        ];
        packet.extend(udp_header);
        
        // QUIC Short Header (first byte + DCID + packet number)
        // First byte: 0xxxxxxx (header form = 0, short header)
        let quic_header = vec![
            0x43,                   // Short header: 0100 0011 (form=0, fixed=1, spin=0, etc.)
            0x01, 0x02, 0x03, 0x04, 0x05, // DCID (connection ID)
            0x00, 0x01,             // Packet number (simplified)
        ];
        packet.extend(quic_header);
        
        packet
    }

    #[test]
    fn test_quic_long_header_first_byte() {
        let packet = create_ipv6_quic_long_header_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let first_byte = parser.parse_field(FieldId::QuicFirstByte).unwrap();
        assert!(first_byte.is_some(), "Should have QUIC first byte");
        
        match first_byte.unwrap() {
            FieldValue::U8(v) => {
                assert_eq!(*v, 0xC3, "First byte should be 0xC3");
                // Verify MSB (header form) is 1 for long header
                assert_eq!((*v >> 7) & 0x01, 1, "MSB should be 1 for long header");
            },
            _ => panic!("Expected U8 for QUIC first byte"),
        }
    }

    #[test]
    fn test_quic_long_header_version() {
        let packet = create_ipv6_quic_long_header_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let version = parser.parse_field(FieldId::QuicVersion).unwrap();
        assert!(version.is_some(), "Long header should have version");
        
        match version.unwrap() {
            FieldValue::U32(v) => assert_eq!(*v, 1, "Version should be 1"),
            _ => panic!("Expected U32 for QUIC version"),
        }
    }

    #[test]
    fn test_quic_short_header_first_byte() {
        let packet = create_ipv6_quic_short_header_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let first_byte = parser.parse_field(FieldId::QuicFirstByte).unwrap();
        assert!(first_byte.is_some(), "Should have QUIC first byte");
        
        match first_byte.unwrap() {
            FieldValue::U8(v) => {
                assert_eq!(*v, 0x43, "First byte should be 0x43");
                // Verify MSB (header form) is 0 for short header
                assert_eq!((*v >> 7) & 0x01, 0, "MSB should be 0 for short header");
            },
            _ => panic!("Expected U8 for QUIC first byte"),
        }
    }

    #[test]
    fn test_quic_short_header_no_version() {
        let packet = create_ipv6_quic_short_header_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let version = parser.parse_field(FieldId::QuicVersion).unwrap();
        assert!(version.is_none(), "Short header should NOT have version field");
    }

    #[test]
    fn test_non_quic_udp_packet_no_quic_fields() {
        // Standard UDP packet (port 8080, not 443/4433) should not parse QUIC fields
        let packet = create_ipv6_udp_packet();
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let first_byte = parser.parse_field(FieldId::QuicFirstByte).unwrap();
        assert!(first_byte.is_none(), "Non-QUIC UDP packet should not have QUIC fields");
        
        let version = parser.parse_field(FieldId::QuicVersion).unwrap();
        assert!(version.is_none(), "Non-QUIC UDP packet should not have QUIC version");
    }

    #[test]
    fn test_quic_port_4433() {
        // Create packet with port 4433 instead of 443
        let mut packet = create_ipv6_quic_long_header_packet();
        
        // Modify destination port to 4433 (0x1151)
        // UDP header starts at offset 14 (ethernet) + 40 (IPv6) = 54
        // Destination port is at bytes 54+2 and 54+3
        packet[56] = 0x11;
        packet[57] = 0x51;
        
        let mut parser = StreamingParser::new(&packet, Direction::Up).unwrap();
        
        let first_byte = parser.parse_field(FieldId::QuicFirstByte).unwrap();
        assert!(first_byte.is_some(), "Port 4433 should be recognized as QUIC");
    }
}

