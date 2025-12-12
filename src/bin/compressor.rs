//! SCHC Compressor Binary
//!
//! Runs SCHC compression on packets from a pcap file using streaming tree method.

use schc::{RuleSet, FieldContext, build_tree, compress_packet, display_tree, Direction};
use clap::Parser;
use anyhow::{Context, Result};
use pcap_file::pcapng::{PcapNgReader, Block};
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
    
    /// Path to the field context JSON file
    #[arg(short, long)]
    field_context: String,
    
    /// Enable debug mode (show field-by-field comparison)
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    
    /// Maximum number of packets to process (0 = all)
    #[arg(short, long, default_value_t = 0)]
    max_packets: usize,

    /// Direction of the first packet ("UP" or "DOWN")
    #[arg(long, default_value = "UP")]
    first_packet_direction: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load field context
    println!("Loading field context from: {}", args.field_context);
    let field_context = FieldContext::from_file(&args.field_context)
        .context("Failed to load field context")?;
    println!("Loaded {} field definitions\n", field_context.fields.len());
    
    // Load rules
    println!("Loading rules from: {}", args.rules);
    let ruleset = RuleSet::from_file(&args.rules)
        .context("Failed to load rules")?;
    println!("Loaded {} rules\n", ruleset.rules.len());

    // Build rule tree
    println!("Building rule tree...");
    let tree = build_tree(&ruleset.rules, &field_context);
    
    if args.debug {
        display_tree(&tree);
    }
    
    // Open pcapng file
    println!("Opening pcap file: {}", args.pcap);
    let file = File::open(&args.pcap)
        .context("Failed to open pcap file")?;
    let mut reader = PcapNgReader::new(file)
        .context("Failed to create pcapng reader")?;
    
    let mut packet_count = 0;
    let mut compressed_count = 0;
    let mut total_original_bits = 0usize;
    let mut total_compressed_bits = 0usize;

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
                    match compress_packet(&tree, &packet_data, direction, &ruleset.rules, &field_context, args.debug) {
                        Ok(compressed) => {
                            compressed_count += 1;
                            total_original_bits += compressed.original_header_bits;
                            total_compressed_bits += compressed.compressed_header_bits;
                            
                            let savings_bits = compressed.savings_bits();
                            let savings_bytes = compressed.savings_bytes();
                            let original_bytes = compressed.original_header_bits as f64 / 8.0;
                            let compressed_bytes = compressed.compressed_header_bits as f64 / 8.0;
                            
                            if !args.debug {
                                println!("Packet {}: {:.1} bytes -> {:.1} bytes (Rule: {}/{} - Saved: {:.2} bytes / {} bits, {:.1}%)",
                                    packet_count,
                                    original_bytes,
                                    compressed_bytes,
                                    compressed.rule_id, compressed.rule_id_length,
                                    savings_bytes, savings_bits,
                                    if compressed.original_header_bits > 0 {
                                        100.0 * savings_bits as f64 / compressed.original_header_bits as f64
                                    } else {
                                        0.0
                                    }
                                );
                            } else {
                                println!("\n{}", "═".repeat(80));
                                println!("COMPRESSION RESULT");
                                println!("{}", "═".repeat(80));
                                println!("  Original header:   {} bits ({:.1} bytes)", 
                                         compressed.original_header_bits, original_bytes);
                                println!("  Compressed header: {} bits ({:.1} bytes)", 
                                         compressed.compressed_header_bits, compressed_bytes);
                                println!("  Rule used:         {}/{}", 
                                         compressed.rule_id, compressed.rule_id_length);
                                println!("  Savings:           {} bits ({:.2} bytes, {:.1}%)",
                                         savings_bits, savings_bytes,
                                         if compressed.original_header_bits > 0 {
                                             100.0 * savings_bits as f64 / compressed.original_header_bits as f64
                                         } else {
                                             0.0
                                         });
                                println!("  Compressed data:   {}", hex::encode(&compressed.data));
                                println!("{}\n", "═".repeat(80));
                            }
                        }
                        Err(e) => {
                            if args.debug {
                                eprintln!("Packet {}: No matching rule - {}", packet_count, e);
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
    println!("Total original header:      {} bits ({:.1} bytes)", 
             total_original_bits, total_original_bits as f64 / 8.0);
    println!("Total compressed header:    {} bits ({:.1} bytes)", 
             total_compressed_bits, total_compressed_bits as f64 / 8.0);
    
    if total_original_bits > 0 {
        let saved_bits = total_original_bits.saturating_sub(total_compressed_bits);
        let ratio = 100.0 * saved_bits as f64 / total_original_bits as f64;
        println!("Total bits saved:           {} bits ({:.2} bytes, {:.1}%)", 
                 saved_bits, saved_bits as f64 / 8.0, ratio);
        println!("Compression ratio:          {:.2}:1", 
                 total_original_bits as f64 / total_compressed_bits.max(1) as f64);
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
                println!("Initialized MAC mapping: DEV={}, APP={}", 
                         hex::encode(dev_mac.as_ref().unwrap()), 
                         hex::encode(app_mac.as_ref().unwrap()));
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
