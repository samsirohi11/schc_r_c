//! SCHC Live Compressor Binary
//!
//! Captures packets from a live network interface and compresses them using SCHC.
//! Currently only supports compression of outgoing packets (decompression not implemented yet).

use schc::{RuleSet, FieldContext, build_tree, compress_packet, display_tree, Direction};
use clap::Parser;
use anyhow::{Context, Result, bail};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "live_compressor")]
#[command(about = "SCHC (Static Context Header Compression) live packet compressor", long_about = None)]
struct Args {
    /// Network interface name to capture from
    #[arg(short, long)]
    interface: Option<String>,
    
    /// List available network interfaces
    #[arg(long)]
    list_interfaces: bool,
    
    /// Path to the rules JSON file
    #[arg(short, long)]
    rules: Option<String>,
    
    /// Path to the field context JSON file
    #[arg(short, long)]
    field_context: Option<String>,
    
    /// Enable debug mode (show field-by-field comparison)
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    
    /// Maximum number of packets to process (0 = unlimited)
    #[arg(short, long, default_value_t = 0)]
    max_packets: usize,
}

fn list_interfaces() {
    println!("Available network interfaces:\n");
    for iface in datalink::interfaces() {
        let status = if iface.is_up() { "UP" } else { "DOWN" };
        let loopback = if iface.is_loopback() { " (loopback)" } else { "" };
        
        println!("  {} [{}]{}", iface.name, status, loopback);
        
        if !iface.ips.is_empty() {
            for ip in &iface.ips {
                println!("    - {}", ip);
            }
        }
        
        if let Some(mac) = iface.mac {
            println!("    MAC: {}", mac);
        }
        println!();
    }
}

fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return Ok(());
    }
    
    // Require interface, rules, and field_context for capture mode
    let interface_name = args.interface
        .as_ref()
        .context("Interface name required. Use --interface <name> or --list-interfaces to see available interfaces")?;
    
    let rules_path = args.rules
        .as_ref()
        .context("Rules file required. Use --rules <path>")?;
    
    let field_context_path = args.field_context
        .as_ref()
        .context("Field context file required. Use --field-context <path>")?;
    
    // Load field context
    println!("Loading field context from: {}", field_context_path);
    let field_context = FieldContext::from_file(field_context_path)
        .context("Failed to load field context")?;
    println!("Loaded {} field definitions\n", field_context.fields.len());
    
    // Load rules
    println!("Loading rules from: {}", rules_path);
    let ruleset = RuleSet::from_file(rules_path)
        .context("Failed to load rules")?;
    println!("Loaded {} rules\n", ruleset.rules.len());
    
    // Build rule tree
    println!("Building rule tree...");
    let tree = build_tree(&ruleset.rules, &field_context);
    
    if args.debug {
        display_tree(&tree);
    }
    
    // Find the network interface
    let interface = find_interface(interface_name)
        .context(format!("Interface '{}' not found. Use --list-interfaces to see available interfaces", interface_name))?;
    
    println!("Capturing on interface: {} ({})", 
             interface.name,
             if interface.is_up() { "UP" } else { "DOWN" });
    
    if let Some(mac) = interface.mac {
        println!("Interface MAC: {}", mac);
    }
    
    // Create a channel to receive packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("Unsupported channel type for interface '{}'", interface_name),
        Err(e) => bail!("Failed to create datalink channel: {}. You may need to run with elevated privileges (Administrator/sudo).", e),
    };
    
    // Set up Ctrl+C handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n\nReceived Ctrl+C, stopping capture...");
        r.store(false, Ordering::SeqCst);
    }).context("Failed to set Ctrl+C handler")?;
    
    // Statistics
    let mut packet_count = 0usize;
    let mut compressed_count = 0usize;
    let mut failed_count = 0usize;
    let mut total_original_bits = 0usize;
    let mut total_compressed_bits = 0usize;
    
    // Get our MAC address for direction detection
    let our_mac = interface.mac.map(|m| m.octets().to_vec());
    
    println!("\n{}", "=".repeat(80));
    println!("Capturing packets (press Ctrl+C to stop)");
    println!("{}\n", "=".repeat(80));
    
    // Capture loop
    while running.load(Ordering::SeqCst) {
        if args.max_packets > 0 && packet_count >= args.max_packets {
            println!("\nReached max packet limit ({})", args.max_packets);
            break;
        }
        
        match rx.next() {
            Ok(packet_data) => {
                packet_count += 1;
                
                // Determine direction based on source MAC address
                // If source MAC is ours, it's an outgoing (UP) packet
                let direction = if packet_data.len() >= 14 {
                    let src_mac = &packet_data[6..12];
                    if let Some(ref our) = our_mac {
                        if src_mac == our.as_slice() {
                            Direction::Up  // Outgoing
                        } else {
                            Direction::Down  // Incoming
                        }
                    } else {
                        Direction::Up  // Default to UP if we can't determine
                    }
                } else {
                    Direction::Up
                };
                
                // Attempt compression
                match compress_packet(&tree, packet_data, direction, &ruleset.rules, &field_context, args.debug) {
                    Ok(compressed) => {
                        compressed_count += 1;
                        total_original_bits += compressed.original_header_bits;
                        total_compressed_bits += compressed.compressed_header_bits;
                        
                        let savings_bits = compressed.savings_bits();
                        let savings_bytes = compressed.savings_bytes();
                        let original_bytes = compressed.original_header_bits as f64 / 8.0;
                        let compressed_bytes = compressed.compressed_header_bits as f64 / 8.0;
                        let dir_str = if direction == Direction::Up { "OUT" } else { "IN" };
                        
                        if !args.debug {
                            println!("[{}] Packet {}: {:.1}B -> {:.1}B (Rule: {}/{} | Saved: {:.2}B / {} bits, {:.1}%)",
                                dir_str,
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
                            println!("COMPRESSION RESULT [{}]", dir_str);
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
                            println!("  Original data:     {}", hex::encode(&compressed.original_header_data));
                            println!("  Compressed data:   {}", hex::encode(&compressed.data));
                            println!("{}\n", "═".repeat(80));
                        }
                    }
                    Err(_) => {
                        failed_count += 1;
                        if args.debug {
                            let dir_str = if direction == Direction::Up { "OUT" } else { "IN" };
                            eprintln!("[{}] Packet {}: No matching rule", dir_str, packet_count);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading packet: {}", e);
            }
        }
    }
    
    // Print summary
    println!("\n{}", "=".repeat(80));
    println!("SUMMARY");
    println!("{}", "=".repeat(80));
    println!("Total packets captured:     {}", packet_count);
    println!("Successfully compressed:    {}", compressed_count);
    println!("No matching rule:           {}", failed_count);
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
