//! # SCHC Library - Static Context Header Compression
//!
//! [![Crates.io](https://img.shields.io/crates/v/schc.svg)](https://crates.io/crates/schc)
//! [![Documentation](https://docs.rs/schc/badge.svg)](https://docs.rs/schc)
//!
//! A high-performance implementation of the SCHC (Static Context Header Compression)
//! protocol as defined in [RFC 8724](https://www.rfc-editor.org/rfc/rfc8724).
//!
//! ## Features
//!
//! - **Streaming Tree Architecture** - Fields are parsed on-demand during tree traversal
//! - **Hierarchical Rule Matching** - O(log n) rule matching via tree structure
//! - **Protocol Support** - IPv4, IPv6, and UDP header compression
//! - **Matching Operators** - equal, ignore, match-mapping, MSB
//! - **Compression Actions** - not-sent, value-sent, mapping-sent, LSB, compute
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use schc::{RuleSet, FieldContext, build_tree, compress_packet, Direction};
//!
//! // Load rules from JSON
//! let ruleset = RuleSet::from_file("rules.json").unwrap();
//! let field_context = FieldContext::default();
//!
//! // Build the rule tree
//! let tree = build_tree(&ruleset.rules, &field_context);
//!
//! // Compress a packet
//! let packet: &[u8] = &[/* ethernet frame bytes */];
//! match compress_packet(&tree, packet, Direction::Up, &ruleset.rules, &field_context, false) {
//!     Ok(compressed) => {
//!         println!("Compressed {} bits to {} bits",
//!             compressed.original_header_bits,
//!             compressed.compressed_header_bits);
//!     }
//!     Err(e) => eprintln!("No matching rule: {}", e),
//! }
//! ```
//!
//! ## Module Organization
//!
//! The library is organized into focused modules:
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`parser`] | On-demand packet field extraction using `StreamingParser` |
//! | [`matcher`] | Field value matching (equal, MSB, match-mapping) |
//! | [`compressor`] | Compression/Decompression Actions (CDAs) |
//! | [`tree`] | Rule tree structures and building |
//! | [`tree_display`] | Tree visualization |
//! | [`streaming_tree`] | Integration layer orchestrating the pipeline |
//!
//! ## Rule Format
//!
//! Rules are defined in JSON format:
//!
//! ```json
//! [
//!   {
//!     "RuleID": 1,
//!     "RuleIDLength": 8,
//!     "Compression": [
//!       { "FID": "IPV6.VER", "TV": 6, "MO": "equal", "CDA": "not-sent" },
//!       { "FID": "UDP.SRC_PORT", "MO": "ignore", "CDA": "value-sent" }
//!     ]
//!   }
//! ]
//! ```

pub mod error;
pub mod field_id;
pub mod field_context;
pub mod rule;

// Core functional modules
pub mod parser;
pub mod matcher;
pub mod compressor;
pub mod tree;
pub mod tree_display;

// Integration layer
pub mod streaming_tree;

// Core error/result types
pub use error::{SchcError, Result};
pub use field_id::FieldId;
pub use field_context::FieldContext;
pub use rule::{Rule, RuleSet, Field, MatchingOperator, CompressionAction};

// Re-export main types from streaming_tree for ease of use
pub use streaming_tree::{
    TreeNode, 
    build_tree, 
    display_tree, 
    compress_packet, 
    display_packet_fields,
    Direction, 
    CompressedPacket,
    FieldValue,
};
