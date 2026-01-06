//! # SCHC Library - Static Context Header Compression

pub mod error;
pub mod field_id;
pub mod rule;

// Core functional modules
pub mod compressor;
pub mod decompressor;
pub mod matcher;
pub mod packet_builder;
pub mod parser;
pub mod tree;
pub mod tree_display;

// Integration layer
pub mod streaming_tree;

// Core error/result types
pub use error::{Result, SchcError};
pub use field_id::FieldId;
pub use rule::{CompressionAction, Field, MatchingOperator, Rule, RuleSet};

// Re-export main types from streaming_tree for ease of use
pub use streaming_tree::{
    CompressedPacket, Direction, FieldValue, TreeNode, build_tree, compress_packet,
    display_packet_fields, display_tree,
};

// Re-export decompression types
pub use decompressor::{DecompressedPacket, decompress_packet, match_rule_id};
pub use packet_builder::{ReconstructedHeaders, build_headers};

// Re-export parser context types
pub use parser::QuicContext;
