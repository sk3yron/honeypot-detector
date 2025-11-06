use std::collections::HashMap;
use crate::utils::Result;

/// Simplified feature extractor (subset of Python features)
/// Extracts the most important features for ML model
pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn new() -> Self {
        Self
    }
    
    /// Extract features from bytecode
    /// Returns features in alphabetical order (matches Python output)
    pub fn extract_features(&self, bytecode: &[u8]) -> Result<HashMap<String, f32>> {
        let code_hex = hex::encode(bytecode).to_uppercase();
        let mut features = HashMap::new();
        
        // Basic stats
        self.add_basic_features(&code_hex, &mut features);
        
        // Opcode frequencies
        self.add_opcode_features(&code_hex, &mut features);
        
        // Function selectors
        self.add_function_features(&code_hex, &mut features);
        
        // Honeypot patterns
        self.add_honeypot_patterns(&code_hex, &mut features);
        
        Ok(features)
    }
    
    fn add_basic_features(&self, code: &str, features: &mut HashMap<String, f32>) {
        let length = code.len() / 2;
        features.insert("bytecode_length".to_string(), length as f32);
        
        // Entropy
        let entropy = self.calculate_entropy(code);
        features.insert("byte_entropy".to_string(), entropy as f32);
        
        // Zero bytes
        let zero_count = code.matches("00").count();
        features.insert("zero_byte_ratio".to_string(), (zero_count as f32) / (length as f32));
        
        // FF bytes
        let ff_count = code.matches("FF").count();
        features.insert("ff_byte_ratio".to_string(), (ff_count as f32) / (length as f32));
    }
    
    fn add_opcode_features(&self, code: &str, features: &mut HashMap<String, f32>) {
        let opcodes = [
            ("delegatecall", "F4"),
            ("selfdestruct", "FF"),
            ("sstore", "55"),
            ("sload", "54"),
            ("call", "F1"),
            ("staticcall", "FA"),
            ("jump", "56"),
            ("jumpi", "57"),
        ];
        
        for (name, opcode) in &opcodes {
            let count = code.matches(opcode).count();
            features.insert(format!("opcode_{}_count", name), count as f32);
        }
    }
    
    fn add_function_features(&self, code: &str, features: &mut HashMap<String, f32>) {
        let selectors = [
            ("isblacklisted", "FE575A87"),
            ("blacklist", "59BF1ABE"),
            ("addblacklist", "F9F92BE4"),
            ("transfer", "A9059CBB"),
            ("transferfrom", "23B872DD"),
            ("approve", "095EA7B3"),
            ("mint", "40C10F19"),
            ("burn", "42966C68"),
        ];
        
        for (name, selector) in &selectors {
            let present = if code.contains(selector) { 1.0 } else { 0.0 };
            features.insert(format!("has_{}", name), present);
        }
        
        // Combinations
        let has_approve = code.contains("095EA7B3");
        let has_transferfrom = code.contains("23B872DD");
        features.insert(
            "has_approve_no_transferfrom".to_string(),
            if has_approve && !has_transferfrom { 1.0 } else { 0.0 }
        );
    }
    
    fn add_honeypot_patterns(&self, code: &str, features: &mut HashMap<String, f32>) {
        // Missing transfer
        features.insert(
            "missing_transfer".to_string(),
            if !code.contains("A9059CBB") { 1.0 } else { 0.0 }
        );
        
        // Has blacklist functions
        let has_blacklist = code.contains("FE575A87") 
            || code.contains("59BF1ABE") 
            || code.contains("F9F92BE4");
        features.insert("has_blacklist_functions".to_string(), if has_blacklist { 1.0 } else { 0.0 });
        
        // Delegatecall to storage pattern
        let delegatecall_count = code.matches("F4").count();
        let sload_count = code.matches("54").count();
        if delegatecall_count > 0 && sload_count > 0 {
            features.insert("delegatecall_to_storage_pattern".to_string(), delegatecall_count.min(10) as f32);
        } else {
            features.insert("delegatecall_to_storage_pattern".to_string(), 0.0);
        }
        
        // Hidden owner checks (CALLER followed by EQ)
        let owner_pattern_count = code.matches("3314").count(); // CALLER EQ
        features.insert("hidden_owner_checks".to_string(), owner_pattern_count as f32);
        
        // Conditional selfdestruct
        let has_selfdestruct = code.contains("FF");
        let has_jumpi = code.contains("57");
        features.insert(
            "conditional_selfdestruct".to_string(),
            if has_selfdestruct && has_jumpi { 1.0 } else { 0.0 }
        );
    }
    
    fn calculate_entropy(&self, code: &str) -> f64 {
        let mut counts = HashMap::new();
        for i in (0..code.len()).step_by(2) {
            if let Some(byte) = code.get(i..i+2) {
                *counts.entry(byte).or_insert(0) += 1;
            }
        }
        
        let total = counts.values().sum::<u32>() as f64;
        let mut entropy = 0.0;
        
        for count in counts.values() {
            let p = *count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature_extraction() {
        let extractor = FeatureExtractor::new();
        
        // Simple bytecode
        let bytecode = hex::decode("6080604052").unwrap();
        let features = extractor.extract_features(&bytecode).unwrap();
        
        assert!(features.contains_key("bytecode_length"));
        assert!(features.contains_key("byte_entropy"));
        assert!(features["bytecode_length"] == 5.0);
    }
    
    #[test]
    fn test_blacklist_detection() {
        let extractor = FeatureExtractor::new();
        
        // Bytecode with blacklist function
        let bytecode = hex::decode("FE575A87").unwrap(); // isBlacklisted selector
        let features = extractor.extract_features(&bytecode).unwrap();
        
        assert_eq!(features["has_isblacklisted"], 1.0);
        assert_eq!(features["has_blacklist_functions"], 1.0);
    }
}