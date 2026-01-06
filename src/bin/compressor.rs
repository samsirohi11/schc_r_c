//! SCHC Compressor Binary
//!
//! Runs SCHC compression on packets from a pcap file using streaming tree method.

use anyhow::{Context, Result};
use clap::Parser;
use pcap_file::pcapng::{Block, PcapNgReader};
use schc::FieldId;
use schc::QuicSession;
use schc::parser::StreamingParser;
use schc::{Direction, RuleSet, build_tree, compress_packet, decompress_packet, display_tree};
use std::fs::File;

#[derive(Parser, Debug)]
#[command(name = "compressor")]
#[command(about = "SCHC (Static Context Header Compression) compressor", long_about = None)]
struct Args {
    /// Path to the rules JSON file
    #[arg(short, long)]
    rules: String,

    /// Path to the pcapng file
    #[arg(short, long)]
    pcap: String,

    /// Enable debug mode (show field-by-field comparison)
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    /// Maximum number of packets to process (0 = all)
    #[arg(short, long, default_value_t = 0)]
    max_packets: usize,

    /// Direction of the first packet ("UP" or "DOWN")
    #[arg(long, default_value = "UP")]
    first_packet_direction: String,

    /// Verify compression by decompressing and comparing with original
    #[arg(short = 'v', long, default_value_t = false)]
    verify: bool,

    /// Enable dynamic QUIC rule generation based on learned connection IDs
    #[arg(long, default_value_t = false)]
    dynamic_quic_rules: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load rules
    println!("Loading rules from: {}", args.rules);
    let mut ruleset = RuleSet::from_file(&args.rules).context("Failed to load rules")?;
    println!("Loaded {} rules\n", ruleset.rules.len());

    // Build rule tree
    println!("Building rule tree...");
    let mut tree = build_tree(&ruleset.rules);

    if args.debug {
        display_tree(&tree);
    }

    // Initialize QUIC session for dynamic rule generation
    // Use rule IDs 240-255 for dynamic rules (8-bit rule IDs)
    let mut quic_session = if args.dynamic_quic_rules {
        println!("Dynamic QUIC rule generation enabled");
        Some(QuicSession::new(240, 250, 8, args.debug))
    } else {
        None
    };

    // Open pcapng file
    println!("Opening pcap file: {}", args.pcap);
    let file = File::open(&args.pcap).context("Failed to open pcap file")?;
    let mut reader = PcapNgReader::new(file).context("Failed to create pcapng reader")?;

    let mut packet_count = 0;
    let mut compressed_count = 0;
    let mut unmatched_count = 0;
    let mut total_original_bits = 0usize;
    let mut total_compressed_bits = 0usize;
    let mut unmatched_header_bits = 0usize;

    let mut dev_mac: Option<Vec<u8>> = None;
    let mut app_mac: Option<Vec<u8>> = None;

    println!("\n{}", "=".repeat(80));
    println!("Processing packets");
    println!("{}\n", "=".repeat(80));

    // Process packets
    loop {
        if args.max_packets > 0 && packet_count >= args.max_packets {
            break;
        }

        match reader.next_block() {
            Some(Ok(block)) => {
                if let Block::EnhancedPacket(epb) = block {
                    packet_count += 1;

                    let packet_data = epb.data.to_vec();

                    // Determine direction from MAC addresses
                    let direction = determine_direction(
                        &packet_data,
                        &mut dev_mac,
                        &mut app_mac,
                        &args.first_packet_direction,
                        args.debug,
                    );

                    // Compress packet using streaming tree
                    match compress_packet(
                        &tree,
                        &packet_data,
                        direction,
                        &ruleset.rules,
                        args.debug,
                    ) {
                        Ok(compressed) => {
                            compressed_count += 1;
                            total_original_bits += compressed.original_header_bits;
                            total_compressed_bits += compressed.compressed_header_bits;

                            // If dynamic QUIC rules are enabled, try to learn connection IDs
                            // Use the matched rule as base for new rules
                            if let Some(ref mut session) = quic_session {
                                // Parse packet to extract QUIC fields
                                if let Ok(mut parser) =
                                    StreamingParser::new(&packet_data, direction)
                                {
                                    // Parse QUIC CID fields (they get cached in the parser)
                                    let _ = parser.parse_field(FieldId::QuicFirstByte);
                                    let _ = parser.parse_field(FieldId::QuicVersion);
                                    let _ = parser.parse_field(FieldId::QuicDcidLen);
                                    let _ = parser.parse_field(FieldId::QuicDcid);
                                    let _ = parser.parse_field(FieldId::QuicScidLen);
                                    let _ = parser.parse_field(FieldId::QuicScid);

                                    // Find the base rule that matched this packet
                                    let base_rule = ruleset.rules.iter().find(|r| {
                                        r.rule_id == compressed.rule_id
                                            && r.rule_id_length == compressed.rule_id_length
                                    });

                                    // Update session with learned CIDs, using base rule
                                    if session.update_from_packet(&parser, base_rule) {
                                        let new_rules = session.take_generated_rules();
                                        let deprecated_rules = session.take_deprecated_rule_ids();

                                        println!(
                                            "\n[QUIC CORECONF] Created {} new rule(s) (total unique DCIDs: {})",
                                            new_rules.len(),
                                            session.unique_dcid_count()
                                        );

                                        for rule in &new_rules {
                                            println!(
                                                "  + NEW Rule {}/{}: {}",
                                                rule.rule_id,
                                                rule.rule_id_length,
                                                rule.comment
                                                    .as_deref()
                                                    .unwrap_or("QUIC specific rule")
                                            );
                                        }

                                        if !deprecated_rules.is_empty() {
                                            println!(
                                                "[QUIC CORECONF] Removing {} deprecated rule(s):",
                                                deprecated_rules.len()
                                            );
                                            for (rule_id, rule_id_length) in &deprecated_rules {
                                                println!(
                                                    "  - Deprecated Rule {}/{}",
                                                    rule_id, rule_id_length
                                                );
                                                ruleset.rules.retain(|r| {
                                                    !(r.rule_id == *rule_id
                                                        && r.rule_id_length == *rule_id_length)
                                                });
                                            }
                                        }

                                        // Add new rules (they have unique IDs, no conflicts)
                                        ruleset.rules.extend(new_rules);
                                        tree = build_tree(&ruleset.rules);
                                        println!(
                                            "[QUIC CORECONF] Tree rebuilt with {} total rules\n",
                                            ruleset.rules.len()
                                        );
                                    }
                                }
                            }

                            let savings_bits = compressed.savings_bits();
                            let original_bytes = (compressed.original_header_bits + 7) / 8;
                            let compressed_bytes = (compressed.compressed_header_bits + 7) / 8; // Padded to byte boundary
                            let savings_bytes = original_bytes.saturating_sub(compressed_bytes);

                            if !args.debug {
                                println!(
                                    "Packet {}: {} bytes -> {} bytes (Rule: {}/{} - Saved: {} bytes / {} bits, {:.1}%)",
                                    packet_count,
                                    original_bytes,
                                    compressed_bytes,
                                    compressed.rule_id,
                                    compressed.rule_id_length,
                                    savings_bytes,
                                    savings_bits,
                                    if compressed.original_header_bits > 0 {
                                        100.0 * savings_bits as f64
                                            / compressed.original_header_bits as f64
                                    } else {
                                        0.0
                                    }
                                );
                            } else {
                                println!("\n{}", "═".repeat(80));
                                println!("COMPRESSION RESULT");
                                println!("{}", "═".repeat(80));
                                println!(
                                    "  Original header:   {} bits ({} bytes)",
                                    compressed.original_header_bits, original_bytes
                                );
                                println!(
                                    "  Compressed header: {} bits ({} bytes, padded to byte boundary)",
                                    compressed.compressed_header_bits, compressed_bytes
                                );
                                println!(
                                    "  Rule used:         {}/{}",
                                    compressed.rule_id, compressed.rule_id_length
                                );
                                println!(
                                    "  Savings:           {} bits ({} bytes, {:.1}%)",
                                    savings_bits,
                                    savings_bytes,
                                    if compressed.original_header_bits > 0 {
                                        100.0 * savings_bits as f64
                                            / compressed.original_header_bits as f64
                                    } else {
                                        0.0
                                    }
                                );
                                println!(
                                    "  Original data:     {}",
                                    hex::encode(&compressed.original_header_data)
                                );
                                println!("  Compressed data:   {}", hex::encode(&compressed.data));
                                println!("{}\n", "═".repeat(80));
                            }

                            // Round-trip verification if enabled
                            if args.verify {
                                // Get the payload (everything after the header)
                                let header_len = compressed.original_header_data.len();
                                let ip_start = 14; // Ethernet header length
                                let payload = if packet_data.len() > ip_start + header_len {
                                    Some(&packet_data[ip_start + header_len..])
                                } else {
                                    None
                                };

                                // Original full packet (IP + transport + payload, without Ethernet)
                                let original_full = &packet_data[ip_start..];

                                match decompress_packet(
                                    &compressed.data,
                                    &ruleset.rules,
                                    direction,
                                    payload,
                                ) {
                                    Ok(decompressed) => {
                                        // Compare full packets (header + payload)
                                        let reconstructed_full = &decompressed.full_data;

                                        // Get header bytes only for display
                                        let original_header = &compressed.original_header_data;
                                        let decompressed_header = &decompressed.header_data;

                                        if original_full == reconstructed_full.as_slice() {
                                            println!("  ✓ Verification: PASSED");
                                        } else {
                                            // Check if difference is only in UDP checksum (bytes 46-47 for IPv6+UDP)
                                            let header_len = decompressed.header_data.len();
                                            let checksum_only = if header_len >= 48 {
                                                // UDP checksum is at bytes 46-47 (IPv6 40 + UDP offset 6)
                                                let mut only_checksum_diff = true;
                                                let min_len = original_full
                                                    .len()
                                                    .min(reconstructed_full.len());
                                                for i in 0..min_len {
                                                    if original_full[i] != reconstructed_full[i]
                                                        && !(i == 46 || i == 47)
                                                    {
                                                        only_checksum_diff = false;
                                                        break;
                                                    }
                                                }
                                                only_checksum_diff
                                                    && original_full.len()
                                                        == reconstructed_full.len()
                                            } else {
                                                false
                                            };

                                            if checksum_only {
                                                println!(
                                                    "  ⚠ Verification: PASSED (checksum differs - likely offloading)"
                                                );
                                            } else {
                                                println!("  ✗ Verification: FAILED");

                                                // Show byte-by-byte diff in debug mode
                                                if args.debug {
                                                    let min_len = original_full
                                                        .len()
                                                        .min(reconstructed_full.len());
                                                    for i in 0..min_len {
                                                        if original_full[i] != reconstructed_full[i]
                                                        {
                                                            println!(
                                                                "    Diff at byte {}: original=0x{:02x}, decompressed=0x{:02x}",
                                                                i,
                                                                original_full[i],
                                                                reconstructed_full[i]
                                                            );
                                                        }
                                                    }
                                                    if original_full.len()
                                                        != reconstructed_full.len()
                                                    {
                                                        println!(
                                                            "    Length mismatch: original={}, decompressed={}",
                                                            original_full.len(),
                                                            reconstructed_full.len()
                                                        );
                                                    }
                                                }
                                            }
                                        }

                                        // Always show headers
                                        println!(
                                            "    Original header:      {}",
                                            hex::encode(original_header)
                                        );
                                        println!(
                                            "    Decompressed header:  {}",
                                            hex::encode(decompressed_header)
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("  ✗ Verification ERROR: {}", e);
                                    }
                                }
                            }
                        }
                        Err(_e) => {
                            unmatched_count += 1;
                            // Estimate header size based on IP version
                            // For IPv4: 20 + 8 = 28 bytes = 224 bits (IP + UDP)
                            // For IPv6: 40 + 8 = 48 bytes = 384 bits (IP + UDP)
                            // For non-IP packets: use packet length minus Ethernet header
                            let estimated_header_bytes = if packet_data.len() > 14 {
                                let ip_version = (packet_data[14] >> 4) & 0x0F;
                                match ip_version {
                                    6 => 48,                                   // IPv6 + UDP
                                    4 => 28,                                   // IPv4 + UDP
                                    _ => packet_data.len().saturating_sub(14), // Non-IP: whole packet minus Ethernet
                                }
                            } else {
                                packet_data.len() // Very short packet
                            };
                            let header_bits = estimated_header_bytes * 8;
                            unmatched_header_bits += header_bits;

                            if !args.debug {
                                println!(
                                    "Packet {}: NO MATCH ({} bytes sent uncompressed)",
                                    packet_count, estimated_header_bytes
                                );
                            } else {
                                eprintln!(
                                    "Packet {}: No matching rule - {} ({} bytes)",
                                    packet_count, _e, estimated_header_bytes
                                );
                            }
                        }
                    }
                }
            }
            Some(Err(pcap_file::PcapError::IncompleteBuffer)) => {
                break;
            }
            Some(Err(e)) => {
                eprintln!("Error reading packet: {}", e);
                break;
            }
            None => {
                break;
            }
        }
    }

    // Print summary
    println!("\n{}", "=".repeat(80));
    println!("SUMMARY");
    println!("{}", "=".repeat(80));
    println!("Total packets processed:    {}", packet_count);
    println!("Successfully compressed:    {}", compressed_count);
    println!("Unmatched (sent as-is):     {}", unmatched_count);

    let total_original_bytes = (total_original_bits + unmatched_header_bits + 7) / 8;
    let total_compressed_bytes = (total_compressed_bits + 7) / 8;
    let unmatched_bytes = (unmatched_header_bits + 7) / 8;

    println!(
        "Total original header:      {} bits ({} bytes)",
        total_original_bits + unmatched_header_bits,
        total_original_bytes
    );
    println!(
        "Total compressed header:    {} bits ({} bytes) + {} bytes uncompressed",
        total_compressed_bits, total_compressed_bytes, unmatched_bytes
    );

    if total_original_bits > 0 {
        let saved_bits = total_original_bits.saturating_sub(total_compressed_bits);
        let saved_bytes =
            total_original_bytes.saturating_sub(total_compressed_bytes + unmatched_bytes);
        let ratio = 100.0 * saved_bits as f64 / total_original_bits as f64;
        println!(
            "Total bytes saved:          {} bytes ({} bits, {:.1}%)",
            saved_bytes, saved_bits, ratio
        );
        println!(
            "Compression ratio:          {:.2}:1",
            total_original_bits as f64 / total_compressed_bits.max(1) as f64
        );
    }
    println!("{}", "=".repeat(80));

    Ok(())
}

fn determine_direction(
    packet_data: &[u8],
    dev_mac: &mut Option<Vec<u8>>,
    app_mac: &mut Option<Vec<u8>>,
    first_direction_str: &str,
    debug: bool,
) -> Direction {
    // Extract MACs from ethernet header
    let (src_mac, dst_mac) = if packet_data.len() >= 14 {
        (
            Some(packet_data[6..12].to_vec()),
            Some(packet_data[0..6].to_vec()),
        )
    } else {
        (None, None)
    };

    if dev_mac.is_none() {
        let d = match first_direction_str.to_uppercase().as_str() {
            "DOWN" => Direction::Down,
            _ => Direction::Up,
        };

        if let (Some(src), Some(dst)) = (&src_mac, &dst_mac) {
            match d {
                Direction::Up => {
                    *dev_mac = Some(src.clone());
                    *app_mac = Some(dst.clone());
                }
                Direction::Down => {
                    *dev_mac = Some(dst.clone());
                    *app_mac = Some(src.clone());
                }
            }
            if debug {
                println!(
                    "Initialized MAC mapping: DEV={}, APP={}",
                    hex::encode(dev_mac.as_ref().unwrap()),
                    hex::encode(app_mac.as_ref().unwrap())
                );
            }
        }
        d
    } else {
        if let Some(src) = &src_mac {
            if Some(src) == dev_mac.as_ref() {
                Direction::Up
            } else if Some(src) == app_mac.as_ref() {
                Direction::Down
            } else {
                Direction::Up // Default
            }
        } else {
            Direction::Up
        }
    }
}
