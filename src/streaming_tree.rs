//! Unified Streaming Tree: Parser + Matcher + Compressor Integration
//!
//! This module provides integrated field parsing, rule matching, and compression
//! in a single tree traversal. Fields are parsed on-demand during tree traversal,
//! enabling early pruning when mismatches are detected.
//!
//! The actual implementations are separated into focused modules:
//! - `parser`: StreamingParser for on-demand field extraction
//! - `matcher`: Value matching functions (equal, MSB, mapping)
//! - `compressor`: Compression logic (CDAs)
//! - `tree`: Tree structures and building
//! - `tree_display`: Tree visualization

use crate::error::{Result, SchcError};
use crate::field_id::FieldId;
use crate::rule::{Rule, MatchingOperator, CompressionAction};
use crate::tree::is_coap_option_field;

// Re-export core types from submodules
pub use crate::parser::{Direction, FieldValue, StreamingParser, LinkLayer, parse_packet_fields, display_packet_fields};
pub use crate::tree::{TreeNode, BranchKey, BranchInfo, Branch, build_tree, END_MARKER, find_rule_ids_in_branch};
pub use crate::tree_display::display_tree;
pub use crate::compressor::{CompressedPacket, CompressionResult, FieldCompressionDetail, compress_with_rule};
pub use crate::matcher::{values_match, msb_match, check_branch_match, BranchMatchResult};

// =============================================================================
// Main Compression Entry Point
// =============================================================================

/// Compress a packet using the rule tree (streaming parse + match + compress)
///
/// This is the main entry point that orchestrates the integrated pipeline:
/// 1. Create a streaming parser for the packet
/// 2. Traverse the rule tree matching fields on-demand
/// 3. For each matching rule, compress and collect results
/// 4. Return the best compression result
pub fn compress_packet(
    tree: &TreeNode,
    raw_packet: &[u8],
    direction: Direction,
    rules: &[Rule],
    debug: bool,
) -> Result<CompressedPacket> {
    compress_packet_with_link_layer(tree, raw_packet, direction, rules, debug, LinkLayer::Ethernet)
}

/// Compress a packet with a specified link layer type
///
/// Use this when processing packets without Ethernet headers (e.g., raw IP packets
/// from TUN devices, LPWAN frames, or packets with different link layer types).
pub fn compress_packet_with_link_layer(
    tree: &TreeNode,
    raw_packet: &[u8],
    direction: Direction,
    rules: &[Rule],
    debug: bool,
    link_layer: LinkLayer,
) -> Result<CompressedPacket> {
    let mut parser = StreamingParser::with_link_layer(raw_packet, direction, link_layer)?;
    
    let mut matches: Vec<CompressionResult> = Vec::new();

    if debug {
        println!("\n--- Streaming Tree Traversal ---");
    }

    traverse_and_compress(tree, &mut parser, rules, &mut Vec::new(), &mut matches, debug, 0, &mut TraversalContext::default());

    if matches.is_empty() {
        return Err(SchcError::NoMatchingRule);
    }

    // Find best match: prefer rules with more savings (higher is better)
    // For equal savings, prefer more fields (more complete rule)
    // For equal fields, prefer longer rule_id_length (more specific/dynamic rules)
    // For tie, prefer higher rule_id (newer dynamic rules)
    let best = matches.into_iter()
        .max_by(|a, b| {
            // First: more savings is better
            a.savings_bits.cmp(&b.savings_bits)
                // Then: more fields is better (more complete rule)
                .then_with(|| a.field_count.cmp(&b.field_count))
                // Then: longer rule_id_length is better (more specific rules)
                .then_with(|| a.rule_id_length.cmp(&b.rule_id_length))
                // Finally: higher rule_id is better (newer/dynamic rules)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        })
        .unwrap();

    // Extract original header bytes for display
    let header_bytes = best.original_bits.div_ceil(8);
    let original_header_data = if header_bytes > 0 && raw_packet.len() >= parser.ip_start() + header_bytes {
        raw_packet[parser.ip_start()..parser.ip_start() + header_bytes].to_vec()
    } else {
        Vec::new()
    };

    // Get the payload and append it to the compressed data
    // SCHC compresses headers only; the payload is sent uncompressed after the residues
    let payload = parser.payload().unwrap_or(&[]);
    let mut compressed_data = best.data;
    compressed_data.extend_from_slice(payload);

    if debug && !payload.is_empty() {
        println!("\n--- Payload ---");
        println!("Payload length: {} bytes", payload.len());
        println!("Compressed header: {} bytes, total with payload: {} bytes", 
                 compressed_data.len() - payload.len(), compressed_data.len());
    }

    Ok(CompressedPacket {
        data: compressed_data,
        bit_length: best.compressed_bits,
        rule_id: best.rule_id,
        rule_id_length: best.rule_id_length,
        original_header_bits: best.original_bits,
        compressed_header_bits: best.compressed_bits,
        original_header_data,
    })
}

// =============================================================================
// Traversal Context for CoAP Option Accumulation
// =============================================================================

/// Context passed through tree traversal for CoAP option tracking
#[derive(Debug, Clone, Default)]
struct TraversalContext {
    /// Running cumulative CoAP option number (sum of deltas)
    pub coap_option_number: u16,
}

/// Map a CoAP option FieldId to its absolute option number (RFC 7252)
fn coap_option_field_number(fid: FieldId) -> Option<u16> {
    match fid {
        FieldId::CoapIfMatch => Some(1),
        FieldId::CoapUriHost => Some(3),
        FieldId::CoapEtag => Some(4),
        FieldId::CoapIfNoneMatch => Some(5),
        FieldId::CoapObserve => Some(6),
        FieldId::CoapUriPort => Some(7),
        FieldId::CoapLocationPath => Some(8),
        FieldId::CoapUriPath => Some(11),
        FieldId::CoapContentFormat => Some(12),
        FieldId::CoapMaxAge => Some(14),
        FieldId::CoapUriQuery => Some(15),
        FieldId::CoapAccept => Some(17),
        FieldId::CoapLocationQuery => Some(20),
        FieldId::CoapBlock2 => Some(23),
        FieldId::CoapBlock1 => Some(27),
        FieldId::CoapSize2 => Some(28),
        FieldId::CoapProxyUri => Some(35),
        FieldId::CoapProxyScheme => Some(39),
        FieldId::CoapSize1 => Some(60),
        FieldId::CoapNoResponse => Some(258),
        _ => None,
    }
}

// =============================================================================
// Tree Traversal with Integrated Parse + Match + Compress
// =============================================================================

fn traverse_and_compress(
    node: &TreeNode,
    parser: &mut StreamingParser,
    rules: &[Rule],
    path: &mut Vec<(FieldId, FieldValue, BranchInfo)>,
    matches: &mut Vec<CompressionResult>,
    debug: bool,
    depth: usize,
    ctx: &mut TraversalContext,
) {
    let indent = "  ".repeat(depth);

    if node.is_leaf {
        if let (Some(rule_id), Some(rule_id_length)) = (node.rule_id, node.rule_id_length)
            && let Some(rule) = rules.iter().find(|r| r.rule_id == rule_id && r.rule_id_length == rule_id_length) {
                // Compress using collected path
                let result = compress_with_rule(rule, parser);
                
                if debug {
                    println!("{}└─ ✓ MATCHED Rule {}/{} (savings: {} bits = {:.2} bytes)", 
                             indent, rule_id, rule_id_length, result.savings_bits, result.savings_bits as f64 / 8.0);
                    // Show per-field breakdown
                    for detail in &result.field_details {
                        let cda_str = match detail.cda {
                            CompressionAction::NotSent => "not-sent",
                            CompressionAction::ValueSent => "value-sent",
                            CompressionAction::MappingSent => "mapping-sent",
                            CompressionAction::Lsb => "LSB",
                            CompressionAction::Compute => "compute",
                        };
                        println!("{}   {} ({}): {}b -> {}b = {}b saved",
                                 indent, detail.fid, cda_str, 
                                 detail.original_bits, detail.sent_bits, detail.savings_bits);
                    }
                    println!("{}   Rule ID overhead: {} bits", indent, rule.rule_id_length);
                    println!("{}   Total: {}b original -> {}b compressed = {}b saved",
                             indent, result.original_bits, result.compressed_bits, result.savings_bits);
                }

                matches.push(result);
            }
        return;
    }

    for (key, branches) in &node.branches {
        for branch in branches {
            if key.value == Some(END_MARKER.to_vec()) {
                traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth, ctx);
                continue;
            }

            match check_branch_match(parser, &branch.info) {
                BranchMatchResult::DiSkip => {
                    // Direction Indicator doesn't match - skip this field entirely
                    // Continue to children without parsing/advancing (DI-specific field doesn't apply)
                    if debug {
                        println!("{}├─ - {} [DI skip]: packet_dir={:?} field_di={:?}",
                                 indent, branch.info.fid, parser.direction(), branch.info.di);
                    }
                    traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth, ctx);
                }
                BranchMatchResult::Matched(field_value) => {
                    if debug {
                        let mo_str = match branch.info.mo {
                            MatchingOperator::Equal => "equal".to_string(),
                            MatchingOperator::Ignore => "ignore".to_string(),
                            MatchingOperator::MatchMapping => "mapping".to_string(),
                            MatchingOperator::Msb(n) => format!("MSB({})", n),
                        };
                        let target_str = if let Some(mapping_values) = &branch.info.mapping_tv {
                            let mapping_strs: Vec<String> = mapping_values.iter()
                                .map(|v| v.to_string_repr())
                                .collect();
                            format!("[{}]", mapping_strs.join(", "))
                        } else {
                            branch.info.tv.as_ref().map(|v| v.to_string_repr()).unwrap_or_else(|| "*".to_string())
                        };
                        println!("{}├─ ✓ {} [{}]: packet={} target={}",
                                 indent, branch.info.fid, mo_str,
                                 field_value.as_ref().map(|v| v.as_string()).unwrap_or_else(|| "?".to_string()),
                                 target_str);
                    }
                    if let Some(fv) = field_value {
                        // Track CoAP option numbers: accumulate delta for option fields
                        let prev_coap_option = ctx.coap_option_number;
                        if is_coap_option_field(branch.info.fid) {
                            // The CoAP option number for known fields is the absolute number.
                            // Update the running context with the absolute option number.
                            if let Some(opt_num) = coap_option_field_number(branch.info.fid) {
                                ctx.coap_option_number = opt_num;
                            }
                        }

                        path.push((branch.info.fid, fv, branch.info.clone()));
                        traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth + 1, ctx);
                        path.pop();

                        // Restore context for backtracking
                        ctx.coap_option_number = prev_coap_option;
                    } else {
                        traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth + 1, ctx);
                    }
                }
                BranchMatchResult::NotMatched(field_value) => {
                    if debug {
                        let mo_str = match branch.info.mo {
                            MatchingOperator::Equal => "equal".to_string(),
                            MatchingOperator::Ignore => "ignore".to_string(),
                            MatchingOperator::MatchMapping => "mapping".to_string(),
                            MatchingOperator::Msb(n) => format!("MSB({})", n),
                        };
                        let target_str = if let Some(mapping_values) = &branch.info.mapping_tv {
                            let mapping_strs: Vec<String> = mapping_values.iter()
                                .map(|v| v.to_string_repr())
                                .collect();
                            format!("[{}]", mapping_strs.join(", "))
                        } else {
                            branch.info.tv.as_ref().map(|v| v.to_string_repr()).unwrap_or_else(|| "*".to_string())
                        };
                        let target_rules = find_rule_ids_in_branch(&branch.node);
                        let rule_str = if target_rules.is_empty() {
                            String::new()
                        } else {
                            format!(" -> rule: {}", target_rules.iter()
                                .map(|(id, len)| format!("{}/{}", id, len))
                                .collect::<Vec<_>>()
                                .join(", "))
                        };
                        println!("{}├─ ✗ {} [{}]: packet={} target={}{}",
                                 indent, branch.info.fid, mo_str,
                                 field_value.as_ref().map(|v| v.as_string()).unwrap_or_else(|| "?".to_string()),
                                 target_str, rule_str);
                    }
                    // No match, don't recurse
                }
            }
        }
    }
}
