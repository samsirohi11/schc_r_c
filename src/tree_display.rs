//! Tree Display/Visualization
//!
//! Provides functions to display the rule tree structure in a
//! human-readable format for debugging and analysis.

use crate::tree::{TreeNode, END_MARKER};
use crate::rule::{MatchingOperator, CompressionAction};

// =============================================================================
// Tree Display
// =============================================================================

/// Display the rule tree structure in a formatted way
pub fn display_tree(root: &TreeNode) {
    println!("\n{}", "=".repeat(80));
    println!("SCHC RULE TREE STRUCTURE");
    println!("{}", "=".repeat(80));
    println!("Total nodes: {}", root.count_nodes());
    println!("Total rules (leaves): {}", root.count_leaves());
    println!("{}", "-".repeat(80));
    
    display_node(root, "", true);
    
    println!("{}\n", "=".repeat(80));
}

fn display_node(node: &TreeNode, prefix: &str, is_last: bool) {
    let connector = if is_last { "└─" } else { "├─" };
    let extension = if is_last { "  " } else { "│ " };

    // Only print labels for root and leaf nodes
    if node.is_leaf {
        let label = format!("[RULE {}/{}]", node.rule_id.unwrap_or(0), node.rule_id_length.unwrap_or(0));
        println!("{}{} {}", prefix, connector, label);
        return;
    }
    
    // Print ROOT only
    if node.field_id.is_none() && prefix.is_empty() {
        println!("ROOT");
    }

    let branch_count: usize = node.branches.values().map(|v| v.len()).sum();
    let mut branch_idx = 0;

    for (key, branches) in &node.branches {
        for branch in branches {
            branch_idx += 1;
            let is_last_branch = branch_idx == branch_count;
            let child_prefix = format!("{}{}", prefix, extension);

            // Skip displaying branch info for END markers - just show the leaf directly
            if key.value == Some(END_MARKER.to_vec()) {
                display_node(&branch.node, &child_prefix, is_last_branch);
                continue;
            }

            // Build value string - for match-mapping, show the mapping array
            let value_str = if let Some(mapping_values) = &branch.info.mapping_tv {
                let mapping_strs: Vec<String> = mapping_values.iter()
                    .map(|v| v.to_string_repr())
                    .collect();
                format!("= [{}]", mapping_strs.join(", "))
            } else {
                match &key.value {
                    Some(v) => format!("= 0x{}", hex::encode(v)),
                    None => "= *".to_string(),
                }
            };

            let mo_str = match branch.info.mo {
                MatchingOperator::Equal => "equal".to_string(),
                MatchingOperator::Ignore => "ignore".to_string(),
                MatchingOperator::MatchMapping => "mapping".to_string(),
                MatchingOperator::Msb(n) => format!("MSB({})", n),
            };

            let cda_str = match branch.info.cda {
                CompressionAction::NotSent => "not-sent",
                CompressionAction::ValueSent => "value-sent",
                CompressionAction::MappingSent => "mapping-sent",
                CompressionAction::Lsb => "LSB",
                CompressionAction::Compute => "compute",
            };

            // Get field length info
            let fl_str = if let Some(fl) = branch.info.fl {
                format!(" ({}b)", fl)
            } else if let Some(default_bits) = branch.info.fid.default_size_bits() {
                format!(" ({}b)", default_bits)
            } else {
                String::new()
            };

            let branch_connector = if is_last_branch { "└─" } else { "├─" };
            println!("{}{} {}{} {} | {} | {}", 
                child_prefix, branch_connector,
                branch.info.fid, fl_str, value_str, mo_str, cda_str);

            let next_prefix = format!("{}{}", child_prefix, if is_last_branch { "  " } else { "│ " });
            display_node(&branch.node, &next_prefix, true);
        }
    }
}
