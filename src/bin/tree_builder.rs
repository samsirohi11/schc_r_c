//! Tree Builder Binary
//!
//! Builds and displays the SCHC rule tree structure from a rules JSON file.
//! Supports filtering by direction (Up/Down) to show only relevant fields.

use anyhow::{Context, Result};
use clap::Parser;
use schc::{build_tree, display_tree, display_tree_with_direction, Direction, RuleSet};

#[derive(Parser, Debug)]
#[command(name = "tree_builder")]
#[command(about = "Build and display SCHC rule tree structure", long_about = None)]
struct Args {
    /// Path to the rules JSON file
    #[arg(short, long)]
    rules: String,

    /// Filter tree by direction (up, down, or all)
    #[arg(short, long, default_value = "all")]
    direction: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse direction filter
    let direction_filter = match args.direction.to_lowercase().as_str() {
        "up" => {
            println!("Filter: Up (Device→App) traffic only\n");
            Some(Direction::Up)
        }
        "down" => {
            println!("Filter: Down (App→Device) traffic only\n");
            Some(Direction::Down)
        }
        "all" | _ => {
            println!("Filter: All directions\n");
            None
        }
    };

    // Load rules
    println!("Loading rules from: {}", args.rules);
    let ruleset = RuleSet::from_file(&args.rules).context("Failed to load rules")?;
    println!("Loaded {} rules\n", ruleset.rules.len());

    // Build and display tree
    println!("Building rule tree...");
    let tree = build_tree(&ruleset.rules);

    if direction_filter.is_some() {
        display_tree_with_direction(&tree, direction_filter);
    } else {
        display_tree(&tree);
    }

    Ok(())
}
