//! Simple compression example
//!
//! This example demonstrates basic usage of the SCHC library to compress
//! an IPv6/UDP packet header.

use schc::{RuleSet, FieldContext, build_tree, compress_packet, Direction};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define a simple rule inline
    let rules_json = r#"[
        {
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.TC", "FL": 8, "TV": 0, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.FL", "FL": 20, "MO": "ignore", "CDA": "value-sent"},
                {"FID": "IPV6.NXT", "FL": 8, "TV": 17, "MO": "equal", "CDA": "not-sent"},
                {"FID": "IPV6.HOP_LMT", "FL": 8, "TV": 64, "MO": "equal", "CDA": "not-sent"},
                {"FID": "UDP.SRC_PORT", "FL": 16, "MO": "ignore", "CDA": "value-sent"},
                {"FID": "UDP.DST_PORT", "FL": 16, "MO": "ignore", "CDA": "value-sent"},
                {"FID": "UDP.LEN", "FL": 16, "MO": "ignore", "CDA": "compute"},
                {"FID": "UDP.CKSUM", "FL": 16, "MO": "ignore", "CDA": "compute"}
            ]
        }
    ]"#;

    // Parse rules
    let ruleset = RuleSet::from_json(rules_json)?;
    println!("Loaded {} rule(s)", ruleset.rules.len());

    // Create empty field context (uses defaults)
    let field_context = FieldContext::default();

    // Build the rule tree
    let tree = build_tree(&ruleset.rules, &field_context);
    println!("Built rule tree with {} nodes", tree.count_nodes());

    // Create a sample IPv6/UDP packet with Ethernet header
    let packet = create_sample_ipv6_udp_packet();
    println!("\nPacket size: {} bytes", packet.len());

    // Compress the packet
    match compress_packet(&tree, &packet, Direction::Up, &ruleset.rules, &field_context, false) {
        Ok(result) => {
            println!("\n=== Compression Result ===");
            println!("Rule ID:           {}/{}", result.rule_id, result.rule_id_length);
            println!("Original header:   {} bits ({:.1} bytes)", 
                     result.original_header_bits,
                     result.original_header_bits as f64 / 8.0);
            println!("Compressed header: {} bits ({:.1} bytes)", 
                     result.compressed_header_bits,
                     result.compressed_header_bits as f64 / 8.0);
            println!("Savings:           {} bits ({:.1} bytes, {:.1}%)",
                     result.savings_bits(),
                     result.savings_bytes(),
                     100.0 * result.savings_bits() as f64 / result.original_header_bits as f64);
            println!("Compressed data:   {}", hex::encode(&result.data));
        }
        Err(e) => {
            eprintln!("Compression failed: {}", e);
        }
    }

    Ok(())
}

/// Creates a sample IPv6/UDP packet with Ethernet header
fn create_sample_ipv6_udp_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Source MAC
        0x86, 0xDD,                          // EtherType: IPv6
    ]);
    
    // IPv6 header (40 bytes)
    packet.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00,  // Version=6, TC=0, Flow Label=0
        0x00, 0x10,              // Payload length: 16 bytes
        0x11,                    // Next header: UDP
        0x40,                    // Hop limit: 64
        // Source: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Destination: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]);
    
    // UDP header (8 bytes)
    packet.extend_from_slice(&[
        0x1F, 0x90,  // Source port: 8080
        0x00, 0x50,  // Destination port: 80
        0x00, 0x10,  // Length: 16 bytes (8 header + 8 payload)
        0x00, 0x00,  // Checksum (0 for demo)
    ]);
    
    // UDP payload (8 bytes)
    packet.extend_from_slice(&[
        0x48, 0x65, 0x6C, 0x6C,  // "Hell"
        0x6F, 0x21, 0x0D, 0x0A,  // "o!\r\n"
    ]);
    
    packet
}
