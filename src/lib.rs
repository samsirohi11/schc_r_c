//! # SCHC Library - Static Context Header Compression

pub mod error;
pub mod field_id;
pub mod rule;

// Core functional modules
pub mod parser;
pub mod matcher;
pub mod compressor;
pub mod decompressor;
pub mod packet_builder;
pub mod tree;
pub mod tree_display;

// Integration layer
pub mod streaming_tree;

// Core error/result types
pub use error::{SchcError, Result};
pub use field_id::FieldId;
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

// Re-export decompression types
pub use decompressor::{decompress_packet, match_rule_id, DecompressedPacket};
pub use packet_builder::{build_headers, ReconstructedHeaders};
