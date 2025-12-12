//! Error types for SCHC operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SchcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Packet parse error: {0}")]
    PacketParse(String),
    
    #[error("Compression error: {0}")]
    Compression(String),
    
    #[error("No matching rule found")]
    NoMatchingRule,
    
    #[error("Rule validation error: {0}")]
    RuleValidation(String),
}

pub type Result<T> = std::result::Result<T, SchcError>;
