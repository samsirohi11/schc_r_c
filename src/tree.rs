//! Rule Tree Structures and Building
//!
//! Provides the tree data structures and building logic for organizing
//! compression rules into an efficient hierarchical structure.

use std::collections::HashMap;

use crate::field_id::FieldId;
use crate::rule::{Rule, Field, MatchingOperator, CompressionAction, ParsedTargetValue, RuleValue};

// =============================================================================
// Branch Key and Info
// =============================================================================

/// Branch key for tree node lookups
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BranchKey {
    pub value: Option<Vec<u8>>,
    pub direction: Option<crate::parser::Direction>,
    pub mo_type: u8,  // 0=equal, 1=ignore, 2=match-mapping, 3=MSB
    pub mo_val: Option<u8>,  // For MSB matching
    pub mapping_hash: Option<u64>,  // Hash of mapping values for match-mapping
}

impl BranchKey {
    pub fn new(value: Option<Vec<u8>>, direction: Option<crate::parser::Direction>, mo_type: u8, mo_val: Option<u8>, mapping_hash: Option<u64>) -> Self {
        Self { value, direction, mo_type, mo_val, mapping_hash }
    }
}

/// Information about a branch
#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub fid: FieldId,
    pub mo: MatchingOperator,
    pub mo_val: Option<u8>,
    pub cda: CompressionAction,
    pub tv: Option<RuleValue>,
    pub mapping_tv: Option<Vec<RuleValue>>,  // For match-mapping: list of valid values
    pub fl: Option<u16>,
}

/// A branch connecting to another node
#[derive(Debug, Clone)]
pub struct Branch {
    pub node: TreeNode,
    pub info: BranchInfo,
}

/// End marker for leaf nodes
pub const END_MARKER: &[u8] = b"END";

// =============================================================================
// Tree Node
// =============================================================================

/// A node in the hierarchical rule tree
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub field_id: Option<FieldId>,
    pub branches: HashMap<BranchKey, Vec<Branch>>,
    pub rule_id: Option<u32>,
    pub rule_id_length: Option<u8>,
    pub is_leaf: bool,
}

impl TreeNode {
    pub fn new_field(field_id: FieldId) -> Self {
        Self {
            field_id: Some(field_id),
            branches: HashMap::new(),
            rule_id: None,
            rule_id_length: None,
            is_leaf: false,
        }
    }

    pub fn new_leaf(rule_id: u32, rule_id_length: u8) -> Self {
        Self {
            field_id: None,
            branches: HashMap::new(),
            rule_id: Some(rule_id),
            rule_id_length: Some(rule_id_length),
            is_leaf: true,
        }
    }

    pub fn new_root() -> Self {
        Self {
            field_id: None,
            branches: HashMap::new(),
            rule_id: None,
            rule_id_length: None,
            is_leaf: false,
        }
    }

    pub fn add_branch(&mut self, key: BranchKey, node: TreeNode, info: BranchInfo) {
        let branch = Branch { node, info };
        self.branches.entry(key).or_default().push(branch);
    }

    pub fn count_nodes(&self) -> usize {
        let mut count = 1;
        for branches in self.branches.values() {
            for branch in branches {
                count += branch.node.count_nodes();
            }
        }
        count
    }

    pub fn count_leaves(&self) -> usize {
        if self.is_leaf {
            return 1;
        }
        let mut count = 0;
        for branches in self.branches.values() {
            for branch in branches {
                count += branch.node.count_leaves();
            }
        }
        count
    }
}

// =============================================================================
// Tree Building
// =============================================================================

/// Build a hierarchical tree from compression rules
pub fn build_tree(rules: &[Rule]) -> TreeNode {
    let mut root = TreeNode::new_root();

    for rule in rules {
        if rule.compression.is_empty() {
            continue;
        }
        build_rule_path(&mut root, rule, &rule.compression);
    }

    root
}

fn build_rule_path(root: &mut TreeNode, rule: &Rule, fields: &[Field]) {
    if fields.is_empty() {
        return;
    }

    let first_field = &fields[0];
    let first_fid = first_field.fid;
    let branch_key = get_branch_key(first_field);
    let branch_info = field_to_branch_info(first_field);

    let first_node = if let Some(branches) = root.branches.get_mut(&branch_key) {
        if let Some(branch) = branches.iter_mut().find(|b| b.node.field_id == Some(first_fid)) {
            &mut branch.node
        } else {
            let new_node = TreeNode::new_field(first_fid);
            branches.push(Branch { node: new_node, info: branch_info.clone() });
            &mut branches.last_mut().unwrap().node
        }
    } else {
        let new_node = TreeNode::new_field(first_fid);
        root.add_branch(branch_key.clone(), new_node, branch_info.clone());
        &mut root.branches.get_mut(&branch_key).unwrap().last_mut().unwrap().node
    };

    build_path_recursive(first_node, rule, &fields[1..]);
}

fn build_path_recursive(current: &mut TreeNode, rule: &Rule, remaining: &[Field]) {
    if remaining.is_empty() {
        let leaf = TreeNode::new_leaf(rule.rule_id, rule.rule_id_length);
        let end_key = BranchKey::new(Some(END_MARKER.to_vec()), None, 0, None, None);
        let end_info = BranchInfo {
            fid: FieldId::Ipv6Ver, // Placeholder
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: None,
            mapping_tv: None,
            fl: None,
        };
        current.add_branch(end_key, leaf, end_info);
        return;
    }

    let field = &remaining[0];
    let fid = field.fid;
    let branch_key = get_branch_key(field);
    let branch_info = field_to_branch_info(field);

    let next_node = if let Some(branches) = current.branches.get_mut(&branch_key) {
        if let Some(branch) = branches.iter_mut().find(|b| b.node.field_id == Some(fid)) {
            &mut branch.node
        } else {
            let new_node = TreeNode::new_field(fid);
            branches.push(Branch { node: new_node, info: branch_info.clone() });
            &mut branches.last_mut().unwrap().node
        }
    } else {
        let new_node = TreeNode::new_field(fid);
        current.add_branch(branch_key.clone(), new_node, branch_info.clone());
        &mut current.branches.get_mut(&branch_key).unwrap().last_mut().unwrap().node
    };

    build_path_recursive(next_node, rule, &remaining[1..]);
}

fn get_branch_key(field: &Field) -> BranchKey {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let value = match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => rule_value_to_bytes(rv),
        _ => None,
    };
    
    // Compute MO type as u8
    let mo_type = match field.mo {
        MatchingOperator::Equal => 0,
        MatchingOperator::Ignore => 1,
        MatchingOperator::MatchMapping => 2,
        MatchingOperator::Msb(_) => 3,
    };
    
    // For match-mapping, hash all the mapping values to differentiate branches
    let mapping_hash = match &field.parsed_tv {
        Some(ParsedTargetValue::Mapping(values)) => {
            let mut hasher = DefaultHasher::new();
            for v in values {
                match v {
                    RuleValue::U64(n) => n.hash(&mut hasher),
                    RuleValue::Bytes(b) => b.hash(&mut hasher),
                    RuleValue::String(s) => s.hash(&mut hasher),
                }
            }
            Some(hasher.finish())
        },
        _ => None,
    };
    
    BranchKey::new(value, None, mo_type, field.mo_val, mapping_hash)
}

fn field_to_branch_info(field: &Field) -> BranchInfo {
    let (tv, mapping_tv) = match &field.parsed_tv {
        Some(ParsedTargetValue::Single(rv)) => (Some(rv.clone()), None),
        Some(ParsedTargetValue::Mapping(rv_list)) => (None, Some(rv_list.clone())),
        None => (None, None),
    };

    BranchInfo {
        fid: field.fid,
        mo: field.mo,
        mo_val: field.mo_val,
        cda: field.cda,
        tv,
        mapping_tv,
        fl: field.fl,
    }
}

/// Convert a RuleValue to bytes for branch key
pub fn rule_value_to_bytes(value: &RuleValue) -> Option<Vec<u8>> {
    match value {
        RuleValue::U64(n) => {
            if *n == 0 {
                Some(vec![0])
            } else {
                let bytes = n.to_be_bytes();
                let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
                Some(bytes[start..].to_vec())
            }
        }
        RuleValue::Bytes(b) => Some(b.clone()),
        RuleValue::String(s) => Some(s.as_bytes().to_vec()),
    }
}

// =============================================================================
// Helper: Find Rule IDs in Branch
// =============================================================================

/// Find all rule IDs reachable from a given tree node
pub fn find_rule_ids_in_branch(node: &TreeNode) -> Vec<(u32, u8)> {
    let mut rule_ids = Vec::new();
    collect_rule_ids(node, &mut rule_ids);
    rule_ids
}

fn collect_rule_ids(node: &TreeNode, rule_ids: &mut Vec<(u32, u8)>) {
    if node.is_leaf {
        if let (Some(id), Some(len)) = (node.rule_id, node.rule_id_length) {
            rule_ids.push((id, len));
        }
        return;
    }
    for branches in node.branches.values() {
        for branch in branches {
            collect_rule_ids(&branch.node, rule_ids);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleSet;

    // =========================================================================
    // TreeNode creation tests
    // =========================================================================

    #[test]
    fn test_tree_node_new_root() {
        let root = TreeNode::new_root();
        assert!(root.field_id.is_none());
        assert!(root.rule_id.is_none());
        assert!(root.rule_id_length.is_none());
        assert!(!root.is_leaf);
        assert!(root.branches.is_empty());
    }

    #[test]
    fn test_tree_node_new_field() {
        let node = TreeNode::new_field(FieldId::Ipv6Ver);
        assert_eq!(node.field_id, Some(FieldId::Ipv6Ver));
        assert!(node.rule_id.is_none());
        assert!(!node.is_leaf);
    }

    #[test]
    fn test_tree_node_new_leaf() {
        let leaf = TreeNode::new_leaf(42, 8);
        assert!(leaf.field_id.is_none());
        assert_eq!(leaf.rule_id, Some(42));
        assert_eq!(leaf.rule_id_length, Some(8));
        assert!(leaf.is_leaf);
    }

    // =========================================================================
    // Branch management tests
    // =========================================================================

    #[test]
    fn test_add_branch() {
        let mut root = TreeNode::new_root();
        let child = TreeNode::new_field(FieldId::Ipv6Ver);
        let key = BranchKey::new(Some(vec![6]), None, 0, None, None);
        let info = BranchInfo {
            fid: FieldId::Ipv6Ver,
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: Some(RuleValue::U64(6)),
            mapping_tv: None,
            fl: Some(4),
        };
        
        root.add_branch(key.clone(), child, info);
        
        assert!(root.branches.contains_key(&key));
        assert_eq!(root.branches.get(&key).unwrap().len(), 1);
    }

    #[test]
    fn test_add_multiple_branches_same_key() {
        let mut root = TreeNode::new_root();
        let key = BranchKey::new(None, None, 1, None, None); // Ignore MO
        
        // Add two branches with same key (ignore operator)
        for i in 0..2 {
            let child = TreeNode::new_field(FieldId::Ipv6Tc);
            let info = BranchInfo {
                fid: FieldId::Ipv6Tc,
                mo: MatchingOperator::Ignore,
                mo_val: None,
                cda: CompressionAction::ValueSent,
                tv: None,
                mapping_tv: None,
                fl: Some(8),
            };
            root.add_branch(key.clone(), child, info);
            
            // Should have i+1 branches under this key
            assert_eq!(root.branches.get(&key).unwrap().len(), i + 1);
        }
    }

    // =========================================================================
    // Node counting tests
    // =========================================================================

    #[test]
    fn test_count_nodes_single() {
        let root = TreeNode::new_root();
        assert_eq!(root.count_nodes(), 1);
    }

    #[test]
    fn test_count_nodes_with_children() {
        let mut root = TreeNode::new_root();
        let child = TreeNode::new_field(FieldId::Ipv6Ver);
        let key = BranchKey::new(Some(vec![6]), None, 0, None, None);
        let info = BranchInfo {
            fid: FieldId::Ipv6Ver,
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: Some(RuleValue::U64(6)),
            mapping_tv: None,
            fl: Some(4),
        };
        
        root.add_branch(key, child, info);
        assert_eq!(root.count_nodes(), 2);
    }

    #[test]
    fn test_count_leaves_single_leaf() {
        let leaf = TreeNode::new_leaf(1, 8);
        assert_eq!(leaf.count_leaves(), 1);
    }

    #[test]
    fn test_count_leaves_root_only() {
        let root = TreeNode::new_root();
        assert_eq!(root.count_leaves(), 0);
    }

    #[test]
    fn test_count_leaves_with_children() {
        let mut root = TreeNode::new_root();
        
        // Add two leaf branches
        for i in 0..2 {
            let leaf = TreeNode::new_leaf(i, 8);
            let key = BranchKey::new(Some(vec![i as u8]), None, 0, None, None);
            let info = BranchInfo {
                fid: FieldId::Ipv6Ver,
                mo: MatchingOperator::Equal,
                mo_val: None,
                cda: CompressionAction::NotSent,
                tv: Some(RuleValue::U64(i as u64)),
                mapping_tv: None,
                fl: Some(4),
            };
            root.add_branch(key, leaf, info);
        }
        
        assert_eq!(root.count_leaves(), 2);
    }

    // =========================================================================
    // rule_value_to_bytes tests
    // =========================================================================

    #[test]
    fn test_rule_value_to_bytes_u64_zero() {
        let bytes = rule_value_to_bytes(&RuleValue::U64(0));
        assert_eq!(bytes, Some(vec![0]));
    }

    #[test]
    fn test_rule_value_to_bytes_u64_small() {
        let bytes = rule_value_to_bytes(&RuleValue::U64(255));
        assert_eq!(bytes, Some(vec![255]));
    }

    #[test]
    fn test_rule_value_to_bytes_u64_large() {
        let bytes = rule_value_to_bytes(&RuleValue::U64(0x1234));
        assert_eq!(bytes, Some(vec![0x12, 0x34]));
    }

    #[test]
    fn test_rule_value_to_bytes_bytes() {
        let input = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bytes = rule_value_to_bytes(&RuleValue::Bytes(input.clone()));
        assert_eq!(bytes, Some(input));
    }

    #[test]
    fn test_rule_value_to_bytes_string() {
        let bytes = rule_value_to_bytes(&RuleValue::String("test".to_string()));
        assert_eq!(bytes, Some(b"test".to_vec()));
    }

    // =========================================================================
    // find_rule_ids_in_branch tests
    // =========================================================================

    #[test]
    fn test_find_rule_ids_leaf() {
        let leaf = TreeNode::new_leaf(42, 8);
        let ids = find_rule_ids_in_branch(&leaf);
        assert_eq!(ids, vec![(42, 8)]);
    }

    #[test]
    fn test_find_rule_ids_empty() {
        let root = TreeNode::new_root();
        let ids = find_rule_ids_in_branch(&root);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_find_rule_ids_nested() {
        let mut root = TreeNode::new_root();
        
        // Add nested structure with two leaves
        let mut middle = TreeNode::new_field(FieldId::Ipv6Ver);
        
        let leaf1 = TreeNode::new_leaf(10, 4);
        let key1 = BranchKey::new(Some(END_MARKER.to_vec()), None, 0, None, None);
        let info1 = BranchInfo {
            fid: FieldId::Ipv6Ver,
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: None,
            mapping_tv: None,
            fl: None,
        };
        middle.add_branch(key1, leaf1, info1);
        
        let leaf2 = TreeNode::new_leaf(20, 5);
        let key2 = BranchKey::new(Some(vec![1]), None, 0, None, None);
        let info2 = BranchInfo {
            fid: FieldId::Ipv6Tc,
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: Some(RuleValue::U64(1)),
            mapping_tv: None,
            fl: None,
        };
        middle.add_branch(key2, leaf2, info2);
        
        let middle_key = BranchKey::new(Some(vec![6]), None, 0, None, None);
        let middle_info = BranchInfo {
            fid: FieldId::Ipv6Ver,
            mo: MatchingOperator::Equal,
            mo_val: None,
            cda: CompressionAction::NotSent,
            tv: Some(RuleValue::U64(6)),
            mapping_tv: None,
            fl: Some(4),
        };
        root.add_branch(middle_key, middle, middle_info);
        
        let ids = find_rule_ids_in_branch(&root);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&(10, 4)));
        assert!(ids.contains(&(20, 5)));
    }

    // =========================================================================
    // Tree building from JSON rules tests
    // =========================================================================

    #[test]
    fn test_build_tree_empty_rules() {
        let tree = build_tree(&[]);
        
        assert!(tree.branches.is_empty());
        assert_eq!(tree.count_nodes(), 1); // Just root
        assert_eq!(tree.count_leaves(), 0);
    }

    #[test]
    fn test_build_tree_single_rule() {
        let json = r#"[
            {
                "RuleID": 1,
                "RuleIDLength": 8,
                "Compression": [
                    {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"}
                ]
            }
        ]"#;
        
        let ruleset = RuleSet::from_json(json).unwrap();
        let tree = build_tree(&ruleset.rules);
        
        assert_eq!(tree.count_leaves(), 1);
        
        // Should be able to find rule 1
        let ids = find_rule_ids_in_branch(&tree);
        assert_eq!(ids, vec![(1, 8)]);
    }

    #[test]
    fn test_build_tree_multiple_rules() {
        let json = r#"[
            {
                "RuleID": 1,
                "RuleIDLength": 8,
                "Compression": [
                    {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"}
                ]
            },
            {
                "RuleID": 2,
                "RuleIDLength": 8,
                "Compression": [
                    {"FID": "IPV6.VER", "FL": 4, "TV": 6, "MO": "equal", "CDA": "not-sent"},
                    {"FID": "IPV6.TC", "FL": 8, "TV": 0, "MO": "equal", "CDA": "not-sent"}
                ]
            }
        ]"#;
        
        let ruleset = RuleSet::from_json(json).unwrap();
        let tree = build_tree(&ruleset.rules);
        
        assert_eq!(tree.count_leaves(), 2);
        
        let ids = find_rule_ids_in_branch(&tree);
        assert!(ids.contains(&(1, 8)));
        assert!(ids.contains(&(2, 8)));
    }

    #[test]
    fn test_build_tree_with_ignore_mo() {
        let json = r#"[
            {
                "RuleID": 1,
                "RuleIDLength": 8,
                "Compression": [
                    {"FID": "UDP.LEN", "FL": 16, "MO": "ignore", "CDA": "compute"}
                ]
            }
        ]"#;
        
        let ruleset = RuleSet::from_json(json).unwrap();
        let tree = build_tree(&ruleset.rules);
        
        assert_eq!(tree.count_leaves(), 1);
    }

    #[test]
    fn test_build_tree_skips_empty_compression() {
        let json = r#"[
            {
                "RuleID": 1,
                "RuleIDLength": 8,
                "Compression": []
            }
        ]"#;
        
        let ruleset = RuleSet::from_json(json).unwrap();
        let tree = build_tree(&ruleset.rules);
        
        assert_eq!(tree.count_leaves(), 0); // Empty compression rules are skipped
    }
}
