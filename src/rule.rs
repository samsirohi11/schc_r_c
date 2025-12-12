//! SCHC Rule structures and parsing

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::net::Ipv6Addr;
use crate::error::Result;
use crate::field_id::FieldId;

/// Parsed rule value types
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    U64(u64),
    Bytes(Vec<u8>),
    String(String),
}

impl RuleValue {
    pub fn to_string_repr(&self) -> String {
        match self {
            RuleValue::U64(n) => n.to_string(),
            RuleValue::Bytes(bytes) => {
                if bytes.len() == 8 {
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes[0..8].copy_from_slice(bytes);
                    let addr = Ipv6Addr::from(addr_bytes);
                    format!("{}/64", addr)
                } else {
                    format!("0x{}", hex::encode(bytes))
                }
            },
            RuleValue::String(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParsedTargetValue {
    Single(RuleValue),
    Mapping(Vec<RuleValue>),
}

/// SCHC Compression Rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "RuleID")]
    pub rule_id: u32,
    
    #[serde(rename = "RuleIDLength")]
    pub rule_id_length: u8,
    
    #[serde(rename = "Comment")]
    pub comment: Option<String>,
    
    #[serde(rename = "Compression")]
    pub compression: Vec<Field>,
}

/// Field descriptor within a rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Field {
    #[serde(rename = "FID")]
    pub fid: FieldId,

    #[serde(rename = "FL")]
    pub fl: Option<u16>,
    
    #[serde(rename = "TV")]
    pub tv: Option<serde_json::Value>,
    
    #[serde(rename = "MO")]
    #[serde(deserialize_with = "deserialize_mo")]
    #[serde(serialize_with = "serialize_mo")]
    pub mo: MatchingOperator,
    
    #[serde(rename = "CDA")]
    #[serde(deserialize_with = "deserialize_cda")]
    #[serde(serialize_with = "serialize_cda")]
    pub cda: CompressionAction,

    #[serde(rename = "MO.val")]
    pub mo_val: Option<u8>,

    #[serde(skip)]
    pub parsed_tv: Option<ParsedTargetValue>,
}

impl Field {
    /// Parse target value and apply mo_val to MSB operator.
    /// Returns an error if MO.val exceeds the field length.
    pub fn parse_tv(&mut self) -> crate::error::Result<()> {
        // Apply mo_val to MSB operator
        if let MatchingOperator::Msb(_) = self.mo {
            let mo_val = self.mo_val.unwrap_or(0);
            self.mo = MatchingOperator::Msb(mo_val);
            
            // Get the field length (either explicit FL or default from FieldId)
            let field_length = self.fl
                .or_else(|| self.fid.default_size_bits())
                .unwrap_or(0);
            
            // Validate that MO.val doesn't exceed the field length
            if mo_val as u16 > field_length {
                return Err(crate::error::SchcError::RuleValidation(format!(
                    "Field {}: MO.val ({}) exceeds field length ({} bits)",
                    self.fid, mo_val, field_length
                )));
            }
        }
        
        self.parsed_tv = match (&self.mo, &self.tv) {
            (MatchingOperator::Equal, Some(tv_json)) |
            (MatchingOperator::Msb(_), Some(tv_json)) => {
                parse_single_value(tv_json, self.fid).map(ParsedTargetValue::Single)
            },
            (MatchingOperator::MatchMapping, Some(serde_json::Value::Array(arr))) => {
                let values: Vec<RuleValue> = arr.iter()
                    .filter_map(|json_val| parse_single_value(json_val, self.fid))
                    .collect();
                if values.is_empty() {
                    None
                } else {
                    Some(ParsedTargetValue::Mapping(values))
                }
            },
            _ => None
        };
        
        Ok(())
    }

    /// Get field length in bits if specified
    pub fn get_field_length(&self) -> Option<u16> {
        self.fl
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MatchingOperator {
    Equal,
    Ignore,
    MatchMapping,
    Msb(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionAction {
    NotSent,
    ValueSent,
    MappingSent,
    Lsb(u8),
    Compute,
}

fn deserialize_mo<'de, D>(deserializer: D) -> std::result::Result<MatchingOperator, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(match s.as_str() {
        "equal" => MatchingOperator::Equal,
        "ignore" => MatchingOperator::Ignore,
        "match-mapping" => MatchingOperator::MatchMapping,
        "MSB" => MatchingOperator::Msb(0),
        _ => MatchingOperator::Ignore,
    })
}

fn serialize_mo<S>(mo: &MatchingOperator, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = match mo {
        MatchingOperator::Equal => "equal",
        MatchingOperator::Ignore => "ignore",
        MatchingOperator::MatchMapping => "match-mapping",
        MatchingOperator::Msb(_) => "MSB",
    };
    serializer.serialize_str(s)
}

fn deserialize_cda<'de, D>(deserializer: D) -> std::result::Result<CompressionAction, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(match s.as_str() {
        "not-sent" => CompressionAction::NotSent,
        "value-sent" => CompressionAction::ValueSent,
        "mapping-sent" => CompressionAction::MappingSent,
        "LSB" => CompressionAction::Lsb(0),
        "compute" => CompressionAction::Compute,
        _ => CompressionAction::ValueSent,
    })
}

fn serialize_cda<S>(cda: &CompressionAction, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = match cda {
        CompressionAction::NotSent => "not-sent",
        CompressionAction::ValueSent => "value-sent",
        CompressionAction::MappingSent => "mapping-sent",
        CompressionAction::Lsb(_) => "LSB",
        CompressionAction::Compute => "compute",
    };
    serializer.serialize_str(s)
}

fn parse_single_value(tv_json: &serde_json::Value, fid: FieldId) -> Option<RuleValue> {
    let fid_str = fid.as_str();
    match tv_json {
        serde_json::Value::Number(n) => {
            n.as_u64().map(RuleValue::U64)
        },
        serde_json::Value::String(s) => {
            if fid_str.ends_with("IID") {
                // Try decimal first
                if let Ok(val) = s.parse::<u64>() {
                    return Some(RuleValue::U64(val));
                }
                // Try hex
                let clean_s = s.strip_prefix("0x").unwrap_or(s);
                if let Ok(val) = u64::from_str_radix(clean_s, 16) {
                    Some(RuleValue::U64(val))
                } else {
                    Some(RuleValue::String(s.clone()))
                }
            } else if fid_str.ends_with("PREFIX") {
                let prefix_str = s.split('/').next().unwrap_or(s);
                let clean_prefix_str = if prefix_str.is_empty() { "::" } else { prefix_str };

                if let Ok(addr) = clean_prefix_str.parse::<Ipv6Addr>() {
                    let bytes = addr.octets();
                    let prefix_len = s.split('/')
                        .nth(1)
                        .and_then(|p| p.parse::<usize>().ok())
                        .unwrap_or(64);
                    
                    let prefix_bytes_len = (prefix_len + 7) / 8;
                    let prefix_bytes: Vec<u8> = bytes[..prefix_bytes_len].to_vec();
                    Some(RuleValue::Bytes(prefix_bytes))
                } else {
                    Some(RuleValue::String(s.clone()))
                }
            } else {
                Some(RuleValue::String(s.clone()))
            }
        },
        _ => None,
    }
}

/// Collection of SCHC rules
#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }
    
    pub fn from_json(json: &str) -> Result<Self> {
        let mut rules: Vec<Rule> = serde_json::from_str(json)?;

        for rule in &mut rules {
            // Validate rule ID
            let max_rule_id = (1u64 << rule.rule_id_length) - 1;
            if rule.rule_id as u64 > max_rule_id {
                eprintln!("Warning: Rule {} has ID that exceeds {}-bit range (max: {})",
                    rule.rule_id, rule.rule_id_length, max_rule_id);
            }
            
            for field in &mut rule.compression {
                field.parse_tv()?;
            }
        }
        Ok(RuleSet { rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // MO.val validation tests
    // =========================================================================

    #[test]
    fn test_mo_val_valid_within_field_length() {
        // MO.val = 8 for 16-bit UDP.APP_PORT field - should be valid
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "MO": "MSB", "CDA": "LSB", "MO.val": 8 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_ok(), "Valid MO.val should not error");
    }

    #[test]
    fn test_mo_val_equal_to_field_length() {
        // MO.val = 16 for 16-bit UDP.APP_PORT field - should be valid (edge case)
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "MO": "MSB", "CDA": "LSB", "MO.val": 16 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_ok(), "MO.val equal to field length should be valid");
    }

    #[test]
    fn test_mo_val_exceeds_field_length_error() {
        // MO.val = 20 for 16-bit UDP.APP_PORT field - should error
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "MO": "MSB", "CDA": "LSB", "MO.val": 20 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_err(), "MO.val exceeding field length should error");
        
        // Check error message contains relevant info
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("MO.val"), "Error should mention MO.val");
        assert!(err_msg.contains("20"), "Error should contain the invalid value");
    }

    #[test]
    fn test_mo_val_with_explicit_fl() {
        // MO.val = 14 with explicit FL = 16 - should be valid
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "FL": 16, "MO": "MSB", "CDA": "LSB", "MO.val": 14 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_ok(), "MO.val within explicit FL should be valid");
    }

    #[test]
    fn test_mo_val_exceeds_explicit_fl_error() {
        // MO.val = 20 with explicit FL = 16 - should error
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "FL": 16, "MO": "MSB", "CDA": "LSB", "MO.val": 20 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_err(), "MO.val exceeding explicit FL should error");
    }

    #[test]
    fn test_mo_val_zero_is_valid() {
        // MO.val = 0 should always be valid
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "MO": "MSB", "CDA": "LSB", "MO.val": 0 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_ok(), "MO.val of 0 should be valid");
    }

    #[test]
    fn test_non_msb_mo_ignores_mo_val() {
        // MO = equal should not check MO.val even if present
        let json = r#"[{
            "RuleID": 1,
            "RuleIDLength": 8,
            "Compression": [
                { "FID": "UDP.APP_PORT", "TV": 5680, "MO": "equal", "CDA": "not-sent", "MO.val": 100 }
            ]
        }]"#;
        
        let result = RuleSet::from_json(json);
        assert!(result.is_ok(), "Non-MSB MO should ignore MO.val validation");
    }

    // =========================================================================
    // RuleValue tests
    // =========================================================================

    #[test]
    fn test_rule_value_to_string_repr() {
        assert_eq!(RuleValue::U64(42).to_string_repr(), "42");
        assert_eq!(RuleValue::String("test".to_string()).to_string_repr(), "test");
    }
}
