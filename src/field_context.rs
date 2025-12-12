//! Field context definitions for protocol fields

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use crate::error::Result;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldDefinition {
    pub length: serde_json::Value,
    pub unit: String,
    pub description: String,
    #[serde(default)]
    pub compute: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldContext {
    pub fields: HashMap<String, FieldDefinition>,
}

impl FieldContext {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let context: FieldContext = serde_json::from_str(&content)?;
        Ok(context)
    }
    
    /// Get field length in bits
    pub fn get_field_length_bits(&self, fid: &str) -> Option<u16> {
        let field_def = self.fields.get(fid)?;
        
        match &field_def.length {
            serde_json::Value::Number(n) => n.as_u64().map(|v| v as u16),
            serde_json::Value::String(s) => {
                // Variable length field - return None
                if s.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                    None
                } else {
                    s.parse::<u16>().ok()
                }
            }
            _ => None,
        }
    }
}

impl Default for FieldContext {
    fn default() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }
}

