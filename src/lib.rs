//! # SCHC Library - Static Context Header Compression

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
