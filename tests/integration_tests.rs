//! Integration Tests for SCHC Compression Pipeline
//!
//! These tests verify the complete parse-match-compress pipeline works correctly
//! with real packet data and rule sets.

use schc::{
    RuleSet, FieldContext, build_tree, compress_packet, Direction
};

/// Creates a minimal IPv6/UDP packet with ethernet header
/// Source: 2001:db8:1234:5678:9abc:def0:1234:5678
/// Destination: 2001:db8:abcd:ef01:2345:6789:abcd:ef01
/// UDP Source Port: 8080, Dest Port: 443
fn create_ipv6_udp_packet() -> Vec<u8> {
    // Ethernet header (14 bytes)
    let mut packet = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
        0x86, 0xDD,                          // EtherType (IPv6)
    ];
    
    // IPv6 header (40 bytes)
    let ipv6_header = vec![
        0x60, 0x00, 0x00, 0x00, // Version (6) + TC (0) + Flow Label (0)
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

// =============================================================================
// Basic Pipeline Tests
// =============================================================================

#[test]
fn test_compress_ipv6_version_only() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    assert_eq!(compressed.rule_id, 1);
    assert_eq!(compressed.rule_id_length, 8);
    
    // Original: 4 bits for version
    // Compressed: 8 bits rule ID + 0 bits (not-sent)
    // Net: +4 bits (rule ID overhead exceeds savings for small rules)
    assert!(compressed.original_header_bits == 4);
}

#[test]
fn test_compress_ipv6_multiple_fields() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.TC", "FL": 8, "TV": 0, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.FL", "FL": 20, "MO": "ignore", "CDA": "value-sent"},
                {"FID": "IPV6.NXT", "FL": 8, "TV": 17, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.HOP_LMT", "FL": 8, "TV": 64, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    assert_eq!(compressed.rule_id, 1);
    
    // Original: 4 + 8 + 20 + 8 + 8 = 48 bits
    // Compressed: 8 (rule ID) + 20 (FL value-sent) = 28 bits
    // Savings: 48 - 28 = 20 bits
    assert_eq!(compressed.original_header_bits, 48);
    assert_eq!(compressed.compressed_header_bits, 28);
    assert_eq!(compressed.savings_bits(), 20);
}

#[test]
fn test_compress_no_matching_rule() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 4, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet(); // This has IPv6 version = 6
    
    // Rule expects version = 4, so it shouldn't match
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_err());
}

// =============================================================================
// Rule Selection Tests
// =============================================================================

#[test]
fn test_selects_best_compression_rule() {
    // Two rules that both match, but one provides better compression
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"}
            ]
        },
        {
            "RuleID": 2,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.TC", "FL": 8, "TV": 0, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.NXT", "FL": 8, "TV": 17, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    // Should select rule 2 because it provides more savings (more fields not-sent)
    assert_eq!(compressed.rule_id, 2);
}

// =============================================================================
// Matching Operator Tests
// =============================================================================

#[test]
fn test_ignore_matching_operator() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.LEN", "FL": 16, "MO": "ignore", "CDA": "compute"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    // UDP.LEN with ignore MO should match any value
    assert_eq!(compressed.rule_id, 1);
}

#[test]
fn test_msb_matching_operator() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.SRC_PORT", "FL": 16, "TV": 8080, "MO": "MSB", "MO.val": 8, "CDA": "LSB"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet(); // Has UDP source port 8080 (0x1F90)
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    assert_eq!(compressed.rule_id, 1);
    // MSB(8) match on 8080 (0x1F90) with target 8080 should match (both have 0x1F in top 8 bits)
}

// =============================================================================
// Direction-Based Tests
// =============================================================================

#[test]
fn test_direction_affects_port_matching() {
    // This rule matches DEV port (source in UP, dest in DOWN)
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.DEV_PORT", "FL": 16, "TV": 8080, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet(); // Source: 8080, Dest: 443
    
    // UP direction: DEV_PORT = source = 8080 -> should match
    let result_up = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result_up.is_ok());
    
    // DOWN direction: DEV_PORT = dest = 443 -> should NOT match (expecting 8080)
    let result_down = compress_packet(&tree, &packet, Direction::Down, &ruleset.rules, &field_context, false);
    assert!(result_down.is_err());
}

// =============================================================================
// IPv4 Tests
// =============================================================================

#[test]
fn test_compress_ipv4_packet() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV4.VER", "FL": 4, "TV": 4, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV4.TTL", "FL": 8, "TV": 64, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV4.PROTO", "FL": 8, "TV": 17, "MO": "equal", "CDA": "not-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv4_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    assert_eq!(compressed.rule_id, 1);
    // All three fields are not-sent, only rule ID in output
    assert_eq!(compressed.compressed_header_bits, 8); // Just rule ID
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_ruleset() {
    let ruleset = RuleSet::from_json("[]").unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_err()); // No rules = no match
}

#[test]
fn test_rule_with_empty_compression() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": []
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    // Empty compression rules are skipped during tree building
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_err());
}

// =============================================================================
// Compression Action Tests
// =============================================================================

#[test]
fn test_value_sent_cda() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.SRC_PORT", "FL": 16, "MO": "ignore", "CDA": "value-sent"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet();
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    // 8 bits rule ID + 16 bits UDP port = 24 bits = 3 bytes
    assert_eq!(compressed.compressed_header_bits, 24);
    
    // Verify the port value (8080 = 0x1F90) is in the compressed data
    assert!(compressed.data.len() >= 3);
    // First byte is rule ID (1), next two bytes are port
    assert_eq!(compressed.data[1], 0x1F);
    assert_eq!(compressed.data[2], 0x90);
}

#[test]
fn test_lsb_cda() {
    let json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.SRC_PORT", "FL": 16, "TV": 8080, "MO": "MSB", "MO.val": 8, "CDA": "LSB"}
            ]
        }
    ]"#;
    
    let ruleset = RuleSet::from_json(json).unwrap();
    let field_context = FieldContext::default();
    let tree = build_tree(&ruleset.rules, &field_context);
    let packet = create_ipv6_udp_packet(); // UDP source port 8080 (0x1F90)
    
    let result = compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false);
    assert!(result.is_ok());
    
    let compressed = result.unwrap();
    // 8 bits rule ID + 8 bits LSB = 16 bits = 2 bytes
    assert_eq!(compressed.compressed_header_bits, 16);
    
    // First byte is rule ID (1), second byte is LSB of port (0x90)
    assert_eq!(compressed.data[0], 1);
    assert_eq!(compressed.data[1], 0x90);
}
