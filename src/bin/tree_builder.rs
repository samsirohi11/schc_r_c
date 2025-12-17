//! Tree Builder Binary
//!
//! Builds and displays the SCHC rule tree structure from a rules JSON file.

use schc::{RuleSet, build_tree, display_tree};
use clap::Parser;
use anyhow::{Context, Result};

#[derive(Parser, Debug)]
#[command(name = "tree_builder")]
#[command(about = "Build and display SCHC rule tree structure", long_about = None)]
struct Args {
    /// Path to the rules JSON file
    #[arg(short, long)]
    rules: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load rules
    println!("Loading rules from: {}", args.rules);
    let ruleset = RuleSet::from_file(&args.rules)
        .context("Failed to load rules")?;
    println!("Loaded {} rules\n", ruleset.rules.len());
    
    // Build and display tree
    println!("Building rule tree...");
    let tree = build_tree(&ruleset.rules);
    
    display_tree(&tree);
    
    Ok(())
}
