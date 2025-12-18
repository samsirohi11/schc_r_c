//! QUIC Rule Builder
//!
//! Dynamic generation of SCHC rules based on QUIC connection context.
//! After observing a QUIC handshake, this module can create more specific
//! compression rules that use the actual connection IDs for better compression.

use crate::field_id::FieldId;
use crate::parser::{FieldValue, StreamingParser};
use crate::rule::{Rule, Field, MatchingOperator, CompressionAction, ParsedTargetValue, RuleValue};

/// Connection ID information extracted from QUIC packets
#[derive(Debug, Clone, Default)]
pub struct QuicConnectionInfo {
    /// Destination Connection ID
    pub dcid: Vec<u8>,
    /// Source Connection ID (only for long headers)
    pub scid: Option<Vec<u8>>,
    /// Whether this is for a long header packet
    pub is_long_header: bool,
    /// QUIC version (for long headers)
    pub version: Option<u32>,
}

impl QuicConnectionInfo {
    /// Extract connection info from a parsed packet
    ///
    /// This reads the QUIC fields from the parser's cache after they've been parsed.
    pub fn from_parser(parser: &StreamingParser) -> Option<Self> {
        // Check if we have the first byte parsed
        let first_byte = match parser.parsed_fields.get(&FieldId::QuicFirstByte) {
            Some(FieldValue::U8(v)) => *v,
            _ => return None,
        };
        
        let is_long_header = (first_byte >> 7) & 0x01 == 1;
        
        // Get DCID
        let dcid = match parser.parsed_fields.get(&FieldId::QuicDcid) {
            Some(FieldValue::Bytes(v)) => v.clone(),
            _ => Vec::new(),
        };
        
        if is_long_header {
            // Get version
            let version = match parser.parsed_fields.get(&FieldId::QuicVersion) {
                Some(FieldValue::U32(v)) => Some(*v),
                _ => None,
            };
            
            // Get SCID
            let scid = match parser.parsed_fields.get(&FieldId::QuicScid) {
                Some(FieldValue::Bytes(v)) => Some(v.clone()),
                _ => None,
            };
            
            Some(Self {
                dcid,
                scid,
                is_long_header: true,
                version,
            })
        } else {
            Some(Self {
                dcid,
                scid: None,
                is_long_header: false,
                version: None,
            })
        }
    }
}

/// QUIC Session for tracking connection state and generating rules
///
/// This struct tracks unique connection IDs observed during a QUIC connection
/// and generates specific SCHC rules for them:
/// - Short header rules: specific DCID with `equal` MO and `not-sent` CDA
/// - Long header rule: match-mapping for DCID/SCID lengths and values
pub struct QuicSession {
    /// Rule builder for creating dynamic rules
    builder: QuicRuleBuilder,
    /// Set of known CID values (as hex strings for fast lookup)
    known_dcids: std::collections::HashSet<String>,
    /// Known DCID lengths for long header match-mapping
    dcid_lengths: Vec<u8>,
    /// Known DCID values for long header match-mapping
    dcid_values: Vec<Vec<u8>>,
    /// Known SCID lengths for long header match-mapping
    scid_lengths: Vec<u8>,
    /// Known SCID values for long header match-mapping
    scid_values: Vec<Vec<u8>>,
    /// QUIC version observed
    version: Option<u32>,
    /// Generated rules
    generated_rules: Vec<Rule>,
    /// Whether long header rule needs regeneration
    long_header_dirty: bool,
    /// Debug mode flag
    debug: bool,
}

impl QuicSession {
    /// Create a new QUIC session
    ///
    /// # Arguments
    /// * `long_header_base_id` - Starting rule ID for long header rules
    /// * `short_header_base_id` - Starting rule ID for short header rules
    /// * `rule_id_length` - Bit length of rule IDs
    /// * `debug` - Enable debug output
    pub fn new(
        long_header_base_id: u32,
        short_header_base_id: u32,
        rule_id_length: u8,
        debug: bool,
    ) -> Self {
        Self {
            builder: QuicRuleBuilder::new(long_header_base_id, short_header_base_id, rule_id_length),
            known_dcids: std::collections::HashSet::new(),
            dcid_lengths: Vec::new(), // No 0 - zero-length CIDs use static rules
            dcid_values: Vec::new(),
            scid_lengths: Vec::new(), // No 0 - zero-length CIDs use static rules
            scid_values: Vec::new(),
            version: None,
            generated_rules: Vec::new(),
            long_header_dirty: false,
            debug,
        }
    }

    /// Update session state from a parsed QUIC packet and a base rule
    ///
    /// Call this after parsing each QUIC packet to track connection IDs.
    /// The base_rule is the rule that matched this packet - new rules will
    /// inherit IP/UDP fields from it.
    /// Returns true if new rules were generated.
    pub fn update_from_packet(&mut self, parser: &StreamingParser, base_rule: Option<&Rule>) -> bool {
        let conn_info = match QuicConnectionInfo::from_parser(parser) {
            Some(info) => info,
            None => return false,
        };
        
        // Track version
        if self.version.is_none() {
            self.version = conn_info.version;
        }
        
        // Only learn from long headers (they have both DCID and SCID)
        if !conn_info.is_long_header {
            return false;
        }
        
        let mut rules_generated = false;
        
        // Track DCID for short header rules and long header mapping
        if self.try_add_dcid_rule(&conn_info.dcid, base_rule, "DCID") {
            rules_generated = true;
        }
        
        // Track DCID length and value for long header mapping (both DCID and SCID mappings)
        if !conn_info.dcid.is_empty() {
            let cid_len = conn_info.dcid.len() as u8;
            // Add to both dcid and scid mappings since CIDs can appear in either role
            if !self.dcid_lengths.contains(&cid_len) {
                self.dcid_lengths.push(cid_len);
                self.long_header_dirty = true;
            }
            if !self.scid_lengths.contains(&cid_len) {
                self.scid_lengths.push(cid_len);
                self.long_header_dirty = true;
            }
            if !self.dcid_values.iter().any(|v| v == &conn_info.dcid) {
                self.dcid_values.push(conn_info.dcid.clone());
                self.long_header_dirty = true;
                if self.debug {
                    println!("[QUIC Session] New CID for mapping: {} bytes = {}", 
                             cid_len, hex::encode(&conn_info.dcid));
                }
            }
            if !self.scid_values.iter().any(|v| v == &conn_info.dcid) {
                self.scid_values.push(conn_info.dcid.clone());
                self.long_header_dirty = true;
            }
        }
        
        // Track SCID (becomes DCID in responses) for short header rules
        if let Some(ref scid) = conn_info.scid {
            if self.try_add_dcid_rule(scid, base_rule, "SCID->DCID") {
                rules_generated = true;
            }
            
            // Track SCID length and value for long header mapping (both DCID and SCID mappings)
            if !scid.is_empty() {
                let cid_len = scid.len() as u8;
                // Add to both dcid and scid mappings since CIDs can appear in either role
                if !self.dcid_lengths.contains(&cid_len) {
                    self.dcid_lengths.push(cid_len);
                    self.long_header_dirty = true;
                }
                if !self.scid_lengths.contains(&cid_len) {
                    self.scid_lengths.push(cid_len);
                    self.long_header_dirty = true;
                }
                if !self.dcid_values.iter().any(|v| v == scid) {
                    self.dcid_values.push(scid.clone());
                    self.long_header_dirty = true;
                }
                if !self.scid_values.iter().any(|v| v == scid) {
                    self.scid_values.push(scid.clone());
                    self.long_header_dirty = true;
                    if self.debug {
                        println!("[QUIC Session] New CID for mapping: {} bytes = {}", 
                                 cid_len, hex::encode(scid));
                    }
                }
            }
        }
        
        // Generate or update long header rule if we learned new CID info
        if self.long_header_dirty {
            self.regenerate_long_header_rule(base_rule);
            rules_generated = true;
        }
        
        rules_generated
    }

    /// Regenerate the long header rule with updated CID mappings
    fn regenerate_long_header_rule(&mut self, base_rule: Option<&Rule>) {
        self.long_header_dirty = false;
        
        let rule = self.builder.create_long_header_rule(
            &self.dcid_lengths,
            &self.dcid_values,
            &self.scid_lengths,
            &self.scid_values,
            self.version,
            base_rule,
        );
        
        if self.debug {
            println!("[QUIC Session] Generated long header rule {}/{} with {} DCID values, {} SCID values",
                     rule.rule_id, rule.rule_id_length, 
                     self.dcid_values.len(), self.scid_values.len());
        }
        
        // Remove any previous long header rule we generated (same rule ID)
        self.generated_rules.retain(|r| r.rule_id != rule.rule_id);
        self.generated_rules.push(rule);
    }

    /// Helper to add a short header rule for a DCID if not already known
    fn try_add_dcid_rule(&mut self, dcid: &[u8], base_rule: Option<&Rule>, label: &str) -> bool {
        if dcid.is_empty() {
            return false;
        }
        
        let dcid_key = hex::encode(dcid);
        if self.known_dcids.contains(&dcid_key) {
            return false;
        }
        
        self.known_dcids.insert(dcid_key.clone());
        
        if self.debug {
            println!("[QUIC Session] New {}: {} bytes = {}", label, dcid.len(), dcid_key);
        }
        
        let rule = self.builder.create_short_header_rule(dcid, base_rule);
        
        if self.debug {
            println!("[QUIC Session] Created short header rule {}/{} for {}: {} bytes",
                     rule.rule_id, rule.rule_id_length, label, dcid.len());
        }
        
        self.generated_rules.push(rule);
        true
    }

    /// Get the generated rules
    pub fn generated_rules(&self) -> &[Rule] {
        &self.generated_rules
    }

    /// Take ownership of generated rules (moves them out)
    pub fn take_generated_rules(&mut self) -> Vec<Rule> {
        std::mem::take(&mut self.generated_rules)
    }

    /// Check if rules have been generated
    pub fn has_generated_rules(&self) -> bool {
        !self.generated_rules.is_empty()
    }

    /// Get number of unique DCIDs tracked
    pub fn unique_dcid_count(&self) -> usize {
        self.known_dcids.len()
    }
}

/// Builder for creating SCHC rules based on QUIC connection context
///
/// This allows creating more specific compression rules after observing
/// the QUIC handshake. Rules with specific connection ID values can use
/// "equal" matching with "not-sent" compression to elide the connection IDs.
pub struct QuicRuleBuilder {
    /// Base rule ID for long header rules  
    long_header_base_id: u32,
    /// Base rule ID for short header rules
    short_header_base_id: u32,
    /// Rule ID bit length
    rule_id_length: u8,
    /// Counter for generating unique rule IDs
    rule_counter: u32,
}

impl QuicRuleBuilder {
    /// Create a new QUIC rule builder
    ///
    /// # Arguments
    /// * `long_header_base_id` - Starting rule ID for long header rules
    /// * `short_header_base_id` - Starting rule ID for short header rules
    /// * `rule_id_length` - Bit length of rule IDs (e.g., 8 for 256 rules)
    pub fn new(long_header_base_id: u32, short_header_base_id: u32, rule_id_length: u8) -> Self {
        Self {
            long_header_base_id,
            short_header_base_id,
            rule_id_length,
            rule_counter: 0,
        }
    }

    /// Create a rule for QUIC long header with match-mapping for CID lengths and values
    ///
    /// This rule uses match-mapping to compress DCID/SCID lengths and values.
    /// As new CIDs are learned, the mappings grow to accommodate them.
    ///
    /// # Arguments
    /// * `dcid_lengths` - Known DCID lengths for match-mapping
    /// * `dcid_values` - Known DCID values for match-mapping
    /// * `scid_lengths` - Known SCID lengths for match-mapping
    /// * `scid_values` - Known SCID values for match-mapping
    /// * `version` - Optional QUIC version
    /// * `base_rule` - Optional base rule to clone non-QUIC fields from
    pub fn create_long_header_rule(
        &mut self,
        dcid_lengths: &[u8],
        dcid_values: &[Vec<u8>],
        scid_lengths: &[u8],
        scid_values: &[Vec<u8>],
        version: Option<u32>,
        base_rule: Option<&Rule>,
    ) -> Rule {
        // Use a fixed rule ID for the long header rule (so it can be updated)
        let rule_id = self.long_header_base_id;

        let mut compression_fields = Vec::new();

        // If we have a base rule, copy the IP/UDP fields from it
        if let Some(base) = base_rule {
            for field in &base.compression {
                let fid_str = field.fid.as_str();
                // Skip QUIC fields - we'll add our own
                if fid_str.starts_with("QUIC.") {
                    continue;
                }
                compression_fields.push(field.clone());
            }
        }

        // Add QUIC fields with match-mapping
        
        // QUIC.FIRST_BYTE - use MSB/LSB to match long header (first bit = 1)
        compression_fields.push(create_field(
            FieldId::QuicFirstByte,
            Some(serde_json::json!(128)), // 0x80 = first bit set
            MatchingOperator::Msb(1),
            CompressionAction::Lsb(7),
            Some(1),
        ));

        // QUIC.VERSION - match and elide if version known
        if let Some(ver) = version {
            compression_fields.push(create_field(
                FieldId::QuicVersion,
                Some(serde_json::json!(ver)),
                MatchingOperator::Equal,
                CompressionAction::NotSent,
                None,
            ));
        }

        // QUIC.DCID_LEN - match-mapping for known lengths
        if !dcid_lengths.is_empty() {
            compression_fields.push(create_mapping_field_u8(
                FieldId::QuicDcidLen,
                dcid_lengths,
            ));
        }

        // QUIC.DCID - match-mapping for known values
        if !dcid_values.is_empty() {
            compression_fields.push(create_mapping_field_bytes(
                FieldId::QuicDcid,
                dcid_values,
            ));
        }

        // QUIC.SCID_LEN - match-mapping for known lengths
        if !scid_lengths.is_empty() {
            compression_fields.push(create_mapping_field_u8(
                FieldId::QuicScidLen,
                scid_lengths,
            ));
        }

        // QUIC.SCID - match-mapping for known values
        if !scid_values.is_empty() {
            compression_fields.push(create_mapping_field_bytes(
                FieldId::QuicScid,
                scid_values,
            ));
        }

        Rule {
            rule_id,
            rule_id_length: self.rule_id_length,
            comment: Some(format!(
                "QUIC Long Header - {} DCID values, {} SCID values (match-mapping)",
                dcid_values.len(),
                scid_values.len()
            )),
            compression: compression_fields,
        }
    }

    /// Create a rule for QUIC short header with specific DCID
    ///
    /// Short headers only contain the DCID (no version, no SCID).
    /// The DCID length is known from the connection context.
    ///
    /// # Arguments
    /// * `dcid` - The DCID value to match
    /// * `base_rule` - Optional base rule to clone non-QUIC fields from
    pub fn create_short_header_rule(
        &mut self,
        dcid: &[u8],
        base_rule: Option<&Rule>,
    ) -> Rule {
        let rule_id = self.short_header_base_id + self.rule_counter;
        self.rule_counter += 1;

        let mut compression_fields = Vec::new();

        // If we have a base rule, copy the IP/UDP fields from it
        if let Some(base) = base_rule {
            for field in &base.compression {
                let fid_str = field.fid.as_str();
                // Skip QUIC fields - we'll add our own
                if fid_str.starts_with("QUIC.") {
                    continue;
                }
                compression_fields.push(field.clone());
            }
        }

        // Add QUIC fields for short header

        // QUIC.FIRST_BYTE - use MSB/LSB to match short header (first bit = 0)
        compression_fields.push(create_field(
            FieldId::QuicFirstByte,
            Some(serde_json::json!(0)), // First bit = 0 for short header
            MatchingOperator::Msb(1),
            CompressionAction::Lsb(7),
            Some(1),
        ));

        // QUIC.DCID - match and elide the specific DCID
        // For short headers, we use FL to specify the DCID length
        if !dcid.is_empty() {
            compression_fields.push(create_bytes_field(
                FieldId::QuicDcid,
                dcid,
                MatchingOperator::Equal,
                CompressionAction::NotSent,
                Some((dcid.len() * 8) as u16),
            ));
        }

        Rule {
            rule_id,
            rule_id_length: self.rule_id_length,
            comment: Some(format!("QUIC Short Header - DCID: {} bytes", dcid.len())),
            compression: compression_fields,
        }
    }

    /// Get the next rule ID that would be assigned
    pub fn next_rule_id(&self, is_long_header: bool) -> u32 {
        if is_long_header {
            self.long_header_base_id + self.rule_counter
        } else {
            self.short_header_base_id + self.rule_counter
        }
    }

    /// Reset the rule counter
    pub fn reset_counter(&mut self) {
        self.rule_counter = 0;
    }
}

/// Helper function to create a field with numeric target value
fn create_field(
    fid: FieldId,
    tv: Option<serde_json::Value>,
    mo: MatchingOperator,
    cda: CompressionAction,
    mo_val: Option<u8>,
) -> Field {
    let mut field = Field {
        fid,
        fl: None,
        tv,
        mo,
        cda,
        mo_val,
        parsed_tv: None,
    };
    // Parse the target value
    let _ = field.parse_tv();
    field
}

/// Helper function to create a field with bytes target value
fn create_bytes_field(
    fid: FieldId,
    bytes: &[u8],
    mo: MatchingOperator,
    cda: CompressionAction,
    fl: Option<u16>,
) -> Field {
    // Create hex string representation for JSON
    let hex_str = format!("0x{}", hex::encode(bytes));
    
    let field = Field {
        fid,
        fl,
        tv: Some(serde_json::json!(hex_str)),
        mo,
        cda,
        mo_val: None,
        parsed_tv: Some(ParsedTargetValue::Single(RuleValue::Bytes(bytes.to_vec()))),
    };
    field
}

/// Helper function to create a match-mapping field for u8 values
fn create_mapping_field_u8(fid: FieldId, values: &[u8]) -> Field {
    // Create JSON array for match-mapping
    let tv_array: Vec<serde_json::Value> = values.iter()
        .map(|v| serde_json::json!(*v as u64))
        .collect();
    
    // Create parsed mapping values
    let mapping_values: Vec<RuleValue> = values.iter()
        .map(|v| RuleValue::U64(*v as u64))
        .collect();
    
    Field {
        fid,
        fl: None,
        tv: Some(serde_json::json!(tv_array)),
        mo: MatchingOperator::MatchMapping,
        cda: CompressionAction::MappingSent,
        mo_val: None,
        parsed_tv: Some(ParsedTargetValue::Mapping(mapping_values)),
    }
}

/// Helper function to create a match-mapping field for byte arrays
fn create_mapping_field_bytes(fid: FieldId, values: &[Vec<u8>]) -> Field {
    // Create JSON array for match-mapping (hex strings)
    let tv_array: Vec<serde_json::Value> = values.iter()
        .map(|v| serde_json::json!(format!("0x{}", hex::encode(v))))
        .collect();
    
    // Create parsed mapping values
    let mapping_values: Vec<RuleValue> = values.iter()
        .map(|v| RuleValue::Bytes(v.clone()))
        .collect();
    
    // Determine field length from first value (assuming all are same length)
    // If values have different lengths, this field uses variable length
    let fl = if !values.is_empty() {
        Some((values[0].len() * 8) as u16)
    } else {
        None
    };
    
    Field {
        fid,
        fl,
        tv: Some(serde_json::json!(tv_array)),
        mo: MatchingOperator::MatchMapping,
        cda: CompressionAction::MappingSent,
        mo_val: None,
        parsed_tv: Some(ParsedTargetValue::Mapping(mapping_values)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_long_header_rule() {
        let mut builder = QuicRuleBuilder::new(100, 200, 8);
        
        let dcid_lengths = vec![5u8];
        let dcid_values = vec![vec![0x01, 0x02, 0x03, 0x04, 0x05]];
        let scid_lengths = vec![4u8];
        let scid_values = vec![vec![0xAA, 0xBB, 0xCC, 0xDD]];

        let rule = builder.create_long_header_rule(
            &dcid_lengths, &dcid_values, &scid_lengths, &scid_values, Some(1), None
        );
        
        assert_eq!(rule.rule_id, 100);
        assert_eq!(rule.rule_id_length, 8);
        assert!(rule.comment.as_ref().unwrap().contains("Long Header"));
        
        // Check that DCID field is present with match-mapping
        let dcid_field = rule.compression.iter().find(|f| f.fid == FieldId::QuicDcid);
        assert!(dcid_field.is_some());
        assert_eq!(dcid_field.unwrap().mo, MatchingOperator::MatchMapping);
        assert_eq!(dcid_field.unwrap().cda, CompressionAction::MappingSent);
    }

    #[test]
    fn test_create_short_header_rule() {
        let mut builder = QuicRuleBuilder::new(100, 200, 8);
        
        let dcid = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let rule = builder.create_short_header_rule(&dcid, None);
        
        assert_eq!(rule.rule_id, 200);
        assert_eq!(rule.rule_id_length, 8);
        assert!(rule.comment.as_ref().unwrap().contains("Short Header"));
        
        // Check that DCID field is present
        let dcid_field = rule.compression.iter().find(|f| f.fid == FieldId::QuicDcid);
        assert!(dcid_field.is_some());
        
        // Short header should not have SCID
        let scid_field = rule.compression.iter().find(|f| f.fid == FieldId::QuicScid);
        assert!(scid_field.is_none());
    }

    #[test]
    fn test_rule_counter_increments() {
        let mut builder = QuicRuleBuilder::new(100, 200, 8);
        
        let dcid_lengths = vec![1u8];
        let dcid_values = vec![vec![0x01]];

        let rule1 = builder.create_long_header_rule(
            &dcid_lengths, &dcid_values, &[], &[], Some(1), None
        );
        let rule2 = builder.create_short_header_rule(&[0x02], None);
        
        assert_eq!(rule1.rule_id, 100); // Long header uses fixed ID now
        assert_eq!(rule2.rule_id, 200); // Short header base
    }

    #[test]
    fn test_empty_connection_ids() {
        let mut builder = QuicRuleBuilder::new(100, 200, 8);
        
        // Empty CID arrays
        let dcid_lengths: Vec<u8> = vec![];
        let dcid_values: Vec<Vec<u8>> = vec![];
        let scid_lengths: Vec<u8> = vec![];
        let scid_values: Vec<Vec<u8>> = vec![];

        let rule = builder.create_long_header_rule(
            &dcid_lengths, &dcid_values, &scid_lengths, &scid_values, Some(1), None
        );
        
        // Rule should be created successfully
        assert_eq!(rule.rule_id, 100);
        
        // DCID_LEN should NOT be present when array is empty
        let dcid_len_field = rule.compression.iter().find(|f| f.fid == FieldId::QuicDcidLen);
        assert!(dcid_len_field.is_none());
    }

    #[test]
    fn test_quic_session_basic() {
        let session = QuicSession::new(100, 200, 8, false);
        
        assert!(!session.has_generated_rules());
        assert_eq!(session.unique_dcid_count(), 0);
    }

    #[test]
    fn test_quic_session_generates_rules_for_unique_dcids() {
        // This test simulates what QuicSession does with unique DCIDs
        let mut builder = QuicRuleBuilder::new(100, 200, 8);
        
        let client_dcid = vec![0x01, 0x02, 0x03, 0x04];
        let server_dcid = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        
        // Short header rule for client->server
        let short_rule_cs = builder.create_short_header_rule(&client_dcid, None);
        
        // Short header rule for server->client
        let short_rule_sc = builder.create_short_header_rule(&server_dcid, None);
        
        // Verify rule IDs are sequential
        assert_eq!(short_rule_cs.rule_id, 200);
        assert_eq!(short_rule_sc.rule_id, 201);
    }
}
