//! Tree Builder Binary
//!
//! Builds and displays the SCHC rule tree structure from a rules JSON file.

use schc::{RuleSet, FieldContext, build_tree, display_tree};
use clap::Parser;
use anyhow::{Context, Result};

#[derive(Parser, Debug)]
#[command(name = "tree_builder")]
#[command(about = "Build and display SCHC rule tree structure", long_about = None)]
struct Args {
    /// Path to the rules JSON file
    #[arg(short, long)]
    rules: String,
    
    /// Path to the field context JSON file
    #[arg(short, long)]
    field_context: String,
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
    
    // Build and display tree
    println!("Building rule tree...");
    let tree = build_tree(&ruleset.rules, &field_context);
    
    display_tree(&tree);
    
    Ok(())
}
