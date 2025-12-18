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

// Re-export core types from submodules
pub use crate::parser::{Direction, FieldValue, StreamingParser, parse_packet_fields, display_packet_fields};
pub use crate::tree::{TreeNode, BranchKey, BranchInfo, Branch, build_tree, END_MARKER, find_rule_ids_in_branch};
pub use crate::tree_display::display_tree;
pub use crate::compressor::{CompressedPacket, CompressionResult, FieldCompressionDetail, compress_with_rule};
pub use crate::matcher::{values_match, msb_match, check_branch_match};

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
    let mut parser = StreamingParser::new(raw_packet, direction)?;
    
    let mut matches: Vec<CompressionResult> = Vec::new();

    if debug {
        println!("\n--- Streaming Tree Traversal ---");
    }

    traverse_and_compress(tree, &mut parser, rules, &mut Vec::new(), &mut matches, debug, 0);

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
    let header_bytes = (best.original_bits + 7) / 8;
    let original_header_data = if header_bytes > 0 && raw_packet.len() >= parser.ip_start() + header_bytes {
        raw_packet[parser.ip_start()..parser.ip_start() + header_bytes].to_vec()
    } else {
        Vec::new()
    };

    Ok(CompressedPacket {
        data: best.data,
        bit_length: best.compressed_bits,
        rule_id: best.rule_id,
        rule_id_length: best.rule_id_length,
        original_header_bits: best.original_bits,
        compressed_header_bits: best.compressed_bits,
        original_header_data,
    })
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
) {
    let indent = "  ".repeat(depth);

    if node.is_leaf {
        if let (Some(rule_id), Some(_rule_id_length)) = (node.rule_id, node.rule_id_length) {
            if let Some(rule) = rules.iter().find(|r| r.rule_id == rule_id) {
                // Compress using collected path
                let result = compress_with_rule(rule, parser);
                
                if debug {
                    println!("{}└─ ✓ MATCHED Rule {}/{} (savings: {} bits = {:.2} bytes)", 
                             indent, rule_id, rule.rule_id_length, result.savings_bits, result.savings_bits as f64 / 8.0);
                    // Show per-field breakdown
                    for detail in &result.field_details {
                        let cda_str = match detail.cda {
                            CompressionAction::NotSent => "not-sent",
                            CompressionAction::ValueSent => "value-sent",
                            CompressionAction::MappingSent => "mapping-sent",
                            CompressionAction::Lsb(_) => "LSB",
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
        }
        return;
    }

    for (key, branches) in &node.branches {
        for branch in branches {
            if key.value == Some(END_MARKER.to_vec()) {
                traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth);
                continue;
            }

            if let Some((matched, field_value)) = check_branch_match(parser, &branch.info) {
                if debug {
                    let status = if matched { "✓" } else { "✗" };
                    let mo_str = match branch.info.mo {
                        MatchingOperator::Equal => "equal".to_string(),
                        MatchingOperator::Ignore => "ignore".to_string(),
                        MatchingOperator::MatchMapping => "mapping".to_string(),
                        MatchingOperator::Msb(n) => format!("MSB({})", n),
                    };
                    
                    // Build target string - show mapping array for match-mapping
                    let target_str = if let Some(mapping_values) = &branch.info.mapping_tv {
                        let mapping_strs: Vec<String> = mapping_values.iter()
                            .map(|v| v.to_string_repr())
                            .collect();
                        format!("[{}]", mapping_strs.join(", "))
                    } else {
                        branch.info.tv.as_ref().map(|v| v.to_string_repr()).unwrap_or_else(|| "*".to_string())
                    };
                    
                    // Only show target rule IDs for branches that don't match
                    let rule_str = if !matched {
                        let target_rules = find_rule_ids_in_branch(&branch.node);
                        if target_rules.is_empty() {
                            String::new()
                        } else {
                            format!(" -> rule: {}", target_rules.iter()
                                .map(|(id, len)| format!("{}/{}", id, len))
                                .collect::<Vec<_>>()
                                .join(", "))
                        }
                    } else {
                        String::new()
                    };
                    
                    println!("{}├─ {} {} [{}]: packet={} target={}{}",
                             indent, status, branch.info.fid, mo_str,
                             field_value.as_ref().map(|v| v.as_string()).unwrap_or_else(|| "?".to_string()),
                             target_str, rule_str);
                }

                if matched {
                    if let Some(fv) = field_value {
                        path.push((branch.info.fid, fv, branch.info.clone()));
                    }
                    traverse_and_compress(&branch.node, parser, rules, path, matches, debug, depth + 1);
                    path.pop();
                }
            }
        }
    }
}
