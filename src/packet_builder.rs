//! Packet Header Builder
//!
//! Reconstructs complete protocol headers from decompressed field values.
//! Handles IPv4, IPv6, UDP, and QUIC (partially) header reconstruction with proper
//! byte ordering, checksum computation, and length calculation.

use std::collections::HashMap;

use crate::error::{Result, SchcError};
use crate::field_id::FieldId;
use crate::parser::{Direction, FieldValue};

// =============================================================================
// Header Reconstruction Result
// =============================================================================

/// Result of header reconstruction
#[derive(Debug, Clone)]
pub struct ReconstructedHeaders {
    /// Combined header bytes (Ethernet + IP + Transport)
    pub data: Vec<u8>,
    /// Offset where IP header starts
    pub ip_start: usize,
    /// Offset where transport header starts
    pub transport_start: usize,
    /// IP version (4 or 6)
    pub ip_version: u8,
}

// =============================================================================
// Main Header Building Functions
// =============================================================================

/// Build complete headers from decompressed field values
///
/// Determines the protocol stack from the fields present and builds
/// appropriate headers in order (Ethernet optional, IP, Transport).
pub fn build_headers(
    fields: &HashMap<FieldId, FieldValue>,
    direction: Direction,
    payload: Option<&[u8]>,
) -> Result<ReconstructedHeaders> {
    let payload_len = payload.map(|p| p.len()).unwrap_or(0);
    // Determine IP version from fields
    let has_ipv4 = fields.contains_key(&FieldId::Ipv4Ver);
    let has_ipv6 = fields.contains_key(&FieldId::Ipv6Ver);

    let ip_version = if has_ipv6 {
        6
    } else if has_ipv4 {
        4
    } else {
        return Err(SchcError::Decompression(
            "No IP version field found in decompressed data".to_string(),
        ));
    };

    // Determine transport layer
    let has_udp = fields.contains_key(&FieldId::UdpSrcPort)
        || fields.contains_key(&FieldId::UdpDstPort)
        || fields.contains_key(&FieldId::UdpDevPort)
        || fields.contains_key(&FieldId::UdpAppPort);

    // Determine if QUIC is present
    let has_quic = fields.contains_key(&FieldId::QuicFirstByte);

    // Calculate QUIC header length (dynamically based on connection IDs)
    let quic_len = if has_quic {
        let first_byte = get_field_u8(fields, FieldId::QuicFirstByte).unwrap_or(0);
        let is_long_header = (first_byte & 0x80) != 0;
        if is_long_header {
            // Long header: first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
            let dcid_len = get_field_u8(fields, FieldId::QuicDcidLen).unwrap_or(0) as usize;
            let scid_len = get_field_u8(fields, FieldId::QuicScidLen).unwrap_or(0) as usize;
            1 + 4 + 1 + dcid_len + 1 + scid_len
        } else {
            // Short header: first_byte(1) + dcid
            let dcid_len = match fields.get(&FieldId::QuicDcid) {
                Some(FieldValue::Bytes(b)) => b.len(),
                _ => 0,
            };
            1 + dcid_len
        }
    } else {
        0
    };

    let transport_len = if has_udp { 8 } else { 0 }; // UDP header is 8 bytes

    // Build headers
    let mut data = Vec::new();
    let ip_start = 0; // ethernet header is not compressed

    // Build IP header (payload = transport + quic + actual_payload)
    let ip_header = if ip_version == 6 {
        build_ipv6_header(fields, direction, payload_len + transport_len + quic_len)?
    } else {
        build_ipv4_header(fields, payload_len + transport_len + quic_len)?
    };

    data.extend_from_slice(&ip_header);
    let transport_start = data.len();

    // Build transport header (payload = quic + actual_payload)
    if has_udp {
        // For UDP, the "payload" for length & checksum must include QUIC header + actual payload
        let udp_payload: Vec<u8> = if has_quic {
            let quic_header = build_quic_header(fields)?;
            let mut combined = quic_header;
            if let Some(p) = payload {
                combined.extend_from_slice(p);
            }
            combined
        } else if let Some(p) = payload {
            p.to_vec()
        } else {
            Vec::new()
        };

        let udp_header = build_udp_header(
            fields,
            direction,
            &ip_header,
            ip_version,
            Some(&udp_payload),
        )?;
        data.extend_from_slice(&udp_header);
    }

    // Build QUIC header if present
    if has_quic {
        let quic_header = build_quic_header(fields)?;
        data.extend_from_slice(&quic_header);
    }

    Ok(ReconstructedHeaders {
        data,
        ip_start,
        transport_start,
        ip_version,
    })
}

// =============================================================================
// IPv4 Header Construction
// =============================================================================

/// Build IPv4 header from decompressed fields
///
/// IPv4 Header Format (20 bytes without options):
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |    DSCP   |ECN|         Total Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn build_ipv4_header(fields: &HashMap<FieldId, FieldValue>, payload_len: usize) -> Result<Vec<u8>> {
    let mut header = vec![0u8; 20];

    // Byte 0: Version (4 bits) + IHL (4 bits)
    let version = get_field_u8(fields, FieldId::Ipv4Ver).unwrap_or(4);
    let ihl = get_field_u8(fields, FieldId::Ipv4Ihl).unwrap_or(5);
    header[0] = (version << 4) | (ihl & 0x0F);

    // Byte 1: DSCP (6 bits) + ECN (2 bits)
    let dscp = get_field_u8(fields, FieldId::Ipv4Dscp).unwrap_or(0);
    let ecn = get_field_u8(fields, FieldId::Ipv4Ecn).unwrap_or(0);
    header[1] = (dscp << 2) | (ecn & 0x03);

    // Bytes 2-3: Total Length (compute if needed)
    let total_len = if fields
        .get(&FieldId::Ipv4Len)
        .map(is_compute_placeholder)
        .unwrap_or(true)
    {
        20 + payload_len as u16
    } else {
        get_field_u16(fields, FieldId::Ipv4Len).unwrap_or(0)
    };
    header[2..4].copy_from_slice(&total_len.to_be_bytes());

    // Bytes 4-5: Identification
    let id = get_field_u16(fields, FieldId::Ipv4Id).unwrap_or(0);
    header[4..6].copy_from_slice(&id.to_be_bytes());

    // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
    let flags = get_field_u8(fields, FieldId::Ipv4Flags).unwrap_or(0);
    let frag_off = get_field_u16(fields, FieldId::Ipv4FragOff).unwrap_or(0);
    let flags_frag = ((flags as u16) << 13) | (frag_off & 0x1FFF);
    header[6..8].copy_from_slice(&flags_frag.to_be_bytes());

    // Byte 8: TTL
    let ttl = get_field_u8(fields, FieldId::Ipv4Ttl).unwrap_or(64);
    header[8] = ttl;

    // Byte 9: Protocol
    let proto = get_field_u8(fields, FieldId::Ipv4Proto).unwrap_or(17); // Default UDP
    header[9] = proto;

    // Bytes 10-11: Header Checksum (set to 0, compute later)
    // Will be computed after all other fields are set

    // Bytes 12-15: Source Address
    if let Some(FieldValue::Ipv4(addr)) = fields.get(&FieldId::Ipv4Src) {
        header[12..16].copy_from_slice(&addr.octets());
    }

    // Bytes 16-19: Destination Address
    if let Some(FieldValue::Ipv4(addr)) = fields.get(&FieldId::Ipv4Dst) {
        header[16..20].copy_from_slice(&addr.octets());
    }

    // Compute header checksum
    let checksum = compute_ipv4_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(header)
}

// =============================================================================
// IPv6 Header Construction
// =============================================================================

/// Build IPv6 header from decompressed fields
///
/// IPv6 Header Format (40 bytes):
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |           Flow Label                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn build_ipv6_header(
    fields: &HashMap<FieldId, FieldValue>,
    direction: Direction,
    payload_len: usize,
) -> Result<Vec<u8>> {
    let mut header = vec![0u8; 40];

    // Bytes 0-3: Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    let version = get_field_u8(fields, FieldId::Ipv6Ver).unwrap_or(6);
    let tc = get_field_u8(fields, FieldId::Ipv6Tc).unwrap_or(0);
    let fl = get_field_u32(fields, FieldId::Ipv6Fl).unwrap_or(0);

    // Pack into 4 bytes
    header[0] = (version << 4) | ((tc >> 4) & 0x0F);
    header[1] = ((tc & 0x0F) << 4) | (((fl >> 16) & 0x0F) as u8);
    header[2] = ((fl >> 8) & 0xFF) as u8;
    header[3] = (fl & 0xFF) as u8;

    // Bytes 4-5: Payload Length (compute if needed)
    let payload_length = if fields
        .get(&FieldId::Ipv6Len)
        .map(is_compute_placeholder)
        .unwrap_or(true)
    {
        payload_len as u16
    } else {
        get_field_u16(fields, FieldId::Ipv6Len).unwrap_or(0)
    };
    header[4..6].copy_from_slice(&payload_length.to_be_bytes());

    // Byte 6: Next Header
    let next_header = get_field_u8(fields, FieldId::Ipv6Nxt).unwrap_or(17); // Default UDP
    header[6] = next_header;

    // Byte 7: Hop Limit
    let hop_limit = get_field_u8(fields, FieldId::Ipv6HopLmt).unwrap_or(64);
    header[7] = hop_limit;

    // Bytes 8-23: Source Address (16 bytes)
    let src_addr = build_ipv6_address(fields, direction, true)?;
    header[8..24].copy_from_slice(&src_addr);

    // Bytes 24-39: Destination Address (16 bytes)
    let dst_addr = build_ipv6_address(fields, direction, false)?;
    header[24..40].copy_from_slice(&dst_addr);

    Ok(header)
}

/// Build complete IPv6 address from prefix + IID or full address
fn build_ipv6_address(
    fields: &HashMap<FieldId, FieldValue>,
    direction: Direction,
    is_source: bool,
) -> Result<[u8; 16]> {
    let mut addr = [0u8; 16];

    // First try full address
    let full_fid = if is_source {
        FieldId::Ipv6Src
    } else {
        FieldId::Ipv6Dst
    };
    if let Some(FieldValue::Ipv6(ipv6)) = fields.get(&full_fid) {
        return Ok(ipv6.octets());
    }

    // Try directional prefix + IID
    let (dev_prefix, dev_iid, app_prefix, app_iid) = (
        FieldId::Ipv6DevPrefix,
        FieldId::Ipv6DevIid,
        FieldId::Ipv6AppPrefix,
        FieldId::Ipv6AppIid,
    );

    // Determine which is source/dest based on direction
    let (prefix_fid, iid_fid) = if is_source {
        match direction {
            Direction::Up => (dev_prefix, dev_iid),
            Direction::Down => (app_prefix, app_iid),
        }
    } else {
        match direction {
            Direction::Up => (app_prefix, app_iid),
            Direction::Down => (dev_prefix, dev_iid),
        }
    };

    // Get prefix (first 8 bytes)
    if let Some(value) = fields.get(&prefix_fid) {
        match value {
            FieldValue::Bytes(bytes) => {
                let len = bytes.len().min(8);
                addr[..len].copy_from_slice(&bytes[..len]);
            }
            FieldValue::Ipv6(ipv6) => {
                addr[..8].copy_from_slice(&ipv6.octets()[..8]);
            }
            _ => {}
        }
    }

    // Also try SRC_PREFIX/DST_PREFIX
    let legacy_prefix = if is_source {
        FieldId::Ipv6SrcPrefix
    } else {
        FieldId::Ipv6DstPrefix
    };
    if addr[..8] == [0u8; 8]
        && let Some(value) = fields.get(&legacy_prefix)
        && let FieldValue::Bytes(bytes) = value
    {
        let len = bytes.len().min(8);
        addr[..len].copy_from_slice(&bytes[..len]);
    }

    // Get IID (last 8 bytes)
    if let Some(value) = fields.get(&iid_fid) {
        match value {
            FieldValue::Bytes(bytes) => {
                let len = bytes.len().min(8);
                addr[8..8 + len].copy_from_slice(&bytes[..len]);
            }
            FieldValue::U64(n) => {
                addr[8..16].copy_from_slice(&n.to_be_bytes());
            }
            _ => {}
        }
    }

    // Also try SRC_IID/DST_IID
    let legacy_iid = if is_source {
        FieldId::Ipv6SrcIid
    } else {
        FieldId::Ipv6DstIid
    };
    if addr[8..16] == [0u8; 8]
        && let Some(value) = fields.get(&legacy_iid)
    {
        match value {
            FieldValue::Bytes(bytes) => {
                let len = bytes.len().min(8);
                addr[8..8 + len].copy_from_slice(&bytes[..len]);
            }
            FieldValue::U64(n) => {
                addr[8..16].copy_from_slice(&n.to_be_bytes());
            }
            _ => {}
        }
    }

    Ok(addr)
}

// =============================================================================
// UDP Header Construction
// =============================================================================

/// Build UDP header from decompressed fields
///
/// UDP Header Format (8 bytes):
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Length             |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn build_udp_header(
    fields: &HashMap<FieldId, FieldValue>,
    direction: Direction,
    ip_header: &[u8],
    ip_version: u8,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut header = vec![0u8; 8];
    let payload_len = payload.map(|p| p.len()).unwrap_or(0);

    // Get ports (handle directional fields)
    let src_port = get_port(fields, direction, true);
    let dst_port = get_port(fields, direction, false);

    // Bytes 0-1: Source Port
    header[0..2].copy_from_slice(&src_port.to_be_bytes());

    // Bytes 2-3: Destination Port
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());

    // Bytes 4-5: Length (compute if needed)
    let length = if fields
        .get(&FieldId::UdpLen)
        .map(is_compute_placeholder)
        .unwrap_or(true)
    {
        (8 + payload_len) as u16
    } else {
        get_field_u16(fields, FieldId::UdpLen).unwrap_or(8)
    };
    header[4..6].copy_from_slice(&length.to_be_bytes());

    // Bytes 6-7: Checksum (compute if needed)
    let needs_checksum = fields
        .get(&FieldId::UdpCksum)
        .map(is_compute_placeholder)
        .unwrap_or(true);
    if needs_checksum {
        let actual_payload = payload.unwrap_or(&[]);
        let checksum = compute_udp_checksum(ip_header, ip_version, &header, actual_payload);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
    } else {
        let checksum = get_field_u16(fields, FieldId::UdpCksum).unwrap_or(0);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
    }

    Ok(header)
}

/// Get UDP port handling directional fields
fn get_port(fields: &HashMap<FieldId, FieldValue>, direction: Direction, is_source: bool) -> u16 {
    // First try directional fields
    let dev_port = FieldId::UdpDevPort;
    let app_port = FieldId::UdpAppPort;

    let directional_fid = if is_source {
        match direction {
            Direction::Up => dev_port,
            Direction::Down => app_port,
        }
    } else {
        match direction {
            Direction::Up => app_port,
            Direction::Down => dev_port,
        }
    };

    if let Some(value) = fields.get(&directional_fid)
        && let Some(port) = field_value_to_u16(value)
    {
        return port;
    }

    // Fall back to explicit source/dest
    let explicit_fid = if is_source {
        FieldId::UdpSrcPort
    } else {
        FieldId::UdpDstPort
    };
    if let Some(value) = fields.get(&explicit_fid)
        && let Some(port) = field_value_to_u16(value)
    {
        return port;
    }

    0
}

// =============================================================================
// QUIC Header Construction
// =============================================================================

/// Build QUIC header from decompressed fields
///
/// Reconstructs the QUIC header fields that are part of the compression
/// rule. For long headers: first_byte + version + dcid_len + dcid + scid_len + scid
/// For short headers: first_byte + dcid
fn build_quic_header(fields: &HashMap<FieldId, FieldValue>) -> Result<Vec<u8>> {
    let first_byte = get_field_u8(fields, FieldId::QuicFirstByte).unwrap_or(0);
    let is_long_header = (first_byte & 0x80) != 0;

    let mut header = Vec::new();

    // First byte
    header.push(first_byte);

    if is_long_header {
        // Long header: first_byte + version + dcid_len + dcid + scid_len + scid

        // Version (4 bytes)
        if let Some(value) = fields.get(&FieldId::QuicVersion) {
            let version = match value {
                FieldValue::U32(v) => *v,
                FieldValue::U64(v) => *v as u32,
                FieldValue::U16(v) => *v as u32,
                FieldValue::U8(v) => *v as u32,
                _ => 1, // Default to version 1
            };
            header.extend_from_slice(&version.to_be_bytes());
        } else {
            // Default version 1 if not in fields
            header.extend_from_slice(&1u32.to_be_bytes());
        }

        // DCID Length (1 byte)
        let dcid_len = get_field_u8(fields, FieldId::QuicDcidLen).unwrap_or(0);
        header.push(dcid_len);

        // DCID (variable)
        if dcid_len > 0
            && let Some(FieldValue::Bytes(dcid)) = fields.get(&FieldId::QuicDcid)
        {
            header.extend_from_slice(dcid);
        }

        // SCID Length (1 byte)
        let scid_len = get_field_u8(fields, FieldId::QuicScidLen).unwrap_or(0);
        header.push(scid_len);

        // SCID (variable)
        if scid_len > 0
            && let Some(FieldValue::Bytes(scid)) = fields.get(&FieldId::QuicScid)
        {
            header.extend_from_slice(scid);
        }
    } else {
        // Short header: first_byte + dcid (from FL or context)
        if let Some(FieldValue::Bytes(dcid)) = fields.get(&FieldId::QuicDcid) {
            header.extend_from_slice(dcid);
        }
    }

    Ok(header)
}

// =============================================================================
// Checksum Computation
// =============================================================================

/// Compute IPv4 header checksum (RFC 791)
pub fn compute_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum up 16-bit words, skipping the checksum field (bytes 10-11)
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Compute UDP checksum with pseudo-header (RFC 768, RFC 8200)
pub fn compute_udp_checksum(
    ip_header: &[u8],
    ip_version: u8,
    udp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Build pseudo-header and add to sum
    if ip_version == 4 && ip_header.len() >= 20 {
        // IPv4 pseudo-header: src (4) + dst (4) + zero (1) + proto (1) + udp_len (2)
        for i in (12..20).step_by(2) {
            sum = sum.wrapping_add(((ip_header[i] as u32) << 8) | (ip_header[i + 1] as u32));
        }
        sum = sum.wrapping_add(17); // Protocol: UDP
        let udp_len = ((udp_header[4] as u32) << 8) | (udp_header[5] as u32);
        sum = sum.wrapping_add(udp_len);
    } else if ip_version == 6 && ip_header.len() >= 40 {
        // IPv6 pseudo-header: src (16) + dst (16) + udp_len (4) + zeros (3) + next_header (1)
        for i in (8..40).step_by(2) {
            sum = sum.wrapping_add(((ip_header[i] as u32) << 8) | (ip_header[i + 1] as u32));
        }
        let udp_len = ((udp_header[4] as u32) << 8) | (udp_header[5] as u32);
        sum = sum.wrapping_add(udp_len);
        sum = sum.wrapping_add(17); // Next Header: UDP
    }

    // Add UDP header (skipping checksum field at bytes 6-7)
    for i in (0..udp_header.len()).step_by(2) {
        if i == 6 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < udp_header.len() {
            ((udp_header[i] as u32) << 8) | (udp_header[i + 1] as u32)
        } else {
            (udp_header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Add payload
    for i in (0..payload.len()).step_by(2) {
        let word = if i + 1 < payload.len() {
            ((payload[i] as u32) << 8) | (payload[i + 1] as u32)
        } else {
            (payload[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !sum as u16;

    // UDP checksum of 0 is transmitted as 0xFFFF for IPv6
    if result == 0 && ip_version == 6 {
        0xFFFF
    } else {
        result
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn get_field_u8(fields: &HashMap<FieldId, FieldValue>, fid: FieldId) -> Option<u8> {
    fields.get(&fid).and_then(|v| match v {
        FieldValue::U8(n) => Some(*n),
        FieldValue::U16(n) => Some(*n as u8),
        FieldValue::U32(n) => Some(*n as u8),
        FieldValue::U64(n) => Some(*n as u8),
        _ => None,
    })
}

fn get_field_u16(fields: &HashMap<FieldId, FieldValue>, fid: FieldId) -> Option<u16> {
    fields.get(&fid).and_then(field_value_to_u16)
}

fn get_field_u32(fields: &HashMap<FieldId, FieldValue>, fid: FieldId) -> Option<u32> {
    fields.get(&fid).and_then(|v| match v {
        FieldValue::U8(n) => Some(*n as u32),
        FieldValue::U16(n) => Some(*n as u32),
        FieldValue::U32(n) => Some(*n),
        FieldValue::U64(n) => Some(*n as u32),
        _ => None,
    })
}

fn field_value_to_u16(v: &FieldValue) -> Option<u16> {
    match v {
        FieldValue::U8(n) => Some(*n as u16),
        FieldValue::U16(n) => Some(*n),
        FieldValue::U32(n) => Some(*n as u16),
        FieldValue::U64(n) => Some(*n as u16),
        _ => None,
    }
}

fn is_compute_placeholder(v: &FieldValue) -> bool {
    // Placeholder values inserted by decompression for compute CDA
    // match v {
    //     FieldValue::U16(0) => true,
    //     FieldValue::U8(0) => true,
    //     _ => false,
    // }
    matches!(v, FieldValue::U16(0) | FieldValue::U8(0))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_checksum() {
        // Example from RFC 1071
        let header = vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00,
            0x00, // Checksum placeholder
            0xc0, 0xa8, 0x00, 0x01, // 192.168.0.1
            0xc0, 0xa8, 0x00, 0xc7, // 192.168.0.199
        ];

        let checksum = compute_ipv4_checksum(&header);
        // Verify it's a valid checksum (non-zero)
        assert!(checksum != 0);
    }

    #[test]
    fn test_build_ipv4_header() {
        let mut fields = HashMap::new();
        fields.insert(FieldId::Ipv4Ver, FieldValue::U8(4));
        fields.insert(FieldId::Ipv4Ihl, FieldValue::U8(5));
        fields.insert(FieldId::Ipv4Ttl, FieldValue::U8(64));
        fields.insert(FieldId::Ipv4Proto, FieldValue::U8(17));
        fields.insert(
            FieldId::Ipv4Src,
            FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );
        fields.insert(
            FieldId::Ipv4Dst,
            FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 2)),
        );

        let header = build_ipv4_header(&fields, 100).unwrap();

        assert_eq!(header.len(), 20);
        assert_eq!(header[0], 0x45); // Version 4, IHL 5
        assert_eq!(header[8], 64); // TTL
        assert_eq!(header[9], 17); // Protocol UDP
    }

    #[test]
    fn test_build_ipv6_header() {
        let mut fields = HashMap::new();
        fields.insert(FieldId::Ipv6Ver, FieldValue::U8(6));
        fields.insert(FieldId::Ipv6Tc, FieldValue::U8(0));
        fields.insert(FieldId::Ipv6Fl, FieldValue::U32(0));
        fields.insert(FieldId::Ipv6Nxt, FieldValue::U8(17));
        fields.insert(FieldId::Ipv6HopLmt, FieldValue::U8(64));

        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        fields.insert(FieldId::Ipv6Src, FieldValue::Ipv6(src));
        fields.insert(FieldId::Ipv6Dst, FieldValue::Ipv6(dst));

        let header = build_ipv6_header(&fields, Direction::Up, 100).unwrap();

        assert_eq!(header.len(), 40);
        assert_eq!(header[0] >> 4, 6); // Version 6
        assert_eq!(header[6], 17); // Next Header: UDP
        assert_eq!(header[7], 64); // Hop Limit
    }

    #[test]
    fn test_build_udp_header() {
        let mut fields = HashMap::new();
        fields.insert(FieldId::UdpSrcPort, FieldValue::U16(8080));
        fields.insert(FieldId::UdpDstPort, FieldValue::U16(443));

        // Minimal IPv4 header for checksum
        let ip_header = vec![0u8; 20];

        // 100 bytes of dummy payload
        let payload = vec![0u8; 100];
        let header =
            build_udp_header(&fields, Direction::Up, &ip_header, 4, Some(&payload[..])).unwrap();

        assert_eq!(header.len(), 8);
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 8080); // Src port
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 443); // Dst port
    }
}
