use async_trait::async_trait;
use crate::core::Analyzer;
use crate::models::*;
use crate::utils::Result;

/// Static bytecode pattern analyzer
/// Detects honeypot patterns without ML or simulation
pub struct StaticAnalyzer {
    // Function selectors to check
    blacklist_selectors: Vec<&'static str>,
    critical_functions: Vec<(&'static str, &'static str)>,
    dangerous_opcodes: Vec<(&'static str, &'static str)>,
}

impl StaticAnalyzer {
    pub fn new() -> Self {
        Self {
            blacklist_selectors: vec![
                "FE575A87", // isBlacklisted(address)
                "0ECB93C0", // isBlackListed(address)
                "59BF1ABE", // blacklist(address)
                "F9F92BE4", // addBlackList(address)
                "E4997DC5", // removeBlackList(address)
            ],
            critical_functions: vec![
                ("transfer", "A9059CBB"),
                ("transferFrom", "23B872DD"),
                ("approve", "095EA7B3"),
                ("mint", "40C10F19"),
                ("burn", "42966C68"),
                ("pause", "8456CB59"),
                ("unpause", "3F4BA83A"),
            ],
            dangerous_opcodes: vec![
                ("DELEGATECALL", "F4"),
                ("SELFDESTRUCT", "FF"),
                ("CALLCODE", "F2"),
            ],
        }
    }
    
    fn analyze_bytecode(&self, bytecode: &[u8]) -> (Vec<Finding>, u8) {
        let code_hex = hex::encode(bytecode).to_uppercase();
        let code_len = bytecode.len();
        
        let mut findings = Vec::new();
        let mut risk_score = 0u32;
        
        // 1. Check for blacklist mechanisms
        let blacklist_findings = self.check_blacklist(&code_hex);
        risk_score += blacklist_findings.iter().map(|f| self.severity_score(f.severity)).sum::<u32>();
        findings.extend(blacklist_findings);
        
        // 2. Check critical functions
        let function_findings = self.check_critical_functions(&code_hex);
        risk_score += function_findings.iter().map(|f| self.severity_score(f.severity)).sum::<u32>();
        findings.extend(function_findings);
        
        // 3. Check dangerous opcodes (with better filtering)
        let opcode_findings = self.check_dangerous_opcodes(&code_hex, code_len);
        risk_score += opcode_findings.iter().map(|f| self.severity_score(f.severity)).sum::<u32>();
        findings.extend(opcode_findings);
        
        // 4. Check for suspicious combinations
        let combo_findings = self.check_suspicious_combinations(&code_hex);
        risk_score += combo_findings.iter().map(|f| self.severity_score(f.severity)).sum::<u32>();
        findings.extend(combo_findings);
        
        // Cap at 100
        let final_score = risk_score.min(100) as u8;
        
        (findings, final_score)
    }
    
    fn check_blacklist(&self, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for selector in &self.blacklist_selectors {
            if code.contains(selector) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: Category::BytecodePattern,
                    message: format!("Blacklist function detected (0x{})", selector),
                    evidence: Some(serde_json::json!({
                        "selector": selector,
                        "description": "Contract can blacklist addresses"
                    })),
                });
            }
        }
        
        findings
    }
    
    fn check_critical_functions(&self, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check which critical functions exist
        let mut function_map = std::collections::HashMap::new();
        for (name, selector) in &self.critical_functions {
            function_map.insert(*name, code.contains(selector));
        }
        
        // Missing transfer() is CRITICAL
        if !function_map.get("transfer").unwrap_or(&false) {
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::BytecodePattern,
                message: "Missing transfer() function".to_string(),
                evidence: Some(serde_json::json!({
                    "description": "No standard ERC20 transfer function found"
                })),
            });
        }
        
        // Has approve() but no transferFrom() is CRITICAL
        let has_approve = *function_map.get("approve").unwrap_or(&false);
        let has_transfer_from = *function_map.get("transferFrom").unwrap_or(&false);
        
        if has_approve && !has_transfer_from {
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::Honeypot,
                message: "Broken ERC20: approve() exists but NO transferFrom()".to_string(),
                evidence: Some(serde_json::json!({
                    "description": "Classic honeypot pattern - cannot transfer approved tokens"
                })),
            });
        }
        
        // Has mint() function
        if *function_map.get("mint").unwrap_or(&false) {
            findings.push(Finding {
                severity: Severity::Low,  // Reduced from Medium - many safe tokens have mint
                category: Category::BytecodePattern,
                message: "mint() function exists".to_string(),
                evidence: Some(serde_json::json!({
                    "description": "Owner can mint tokens (common in legitimate contracts)"
                })),
            });
        }
        
        // Has pause/unpause
        let has_pause = *function_map.get("pause").unwrap_or(&false);
        let has_unpause = *function_map.get("unpause").unwrap_or(&false);
        
        if has_pause || has_unpause {
            findings.push(Finding {
                severity: Severity::Medium,  // Reduced from High
                category: Category::BytecodePattern,
                message: "Pausable contract detected".to_string(),
                evidence: Some(serde_json::json!({
                    "description": "Contract can be paused (review pausability conditions)"
                })),
            });
        }
        
        findings
    }
    
    fn check_dangerous_opcodes(&self, code: &str, code_len: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for (name, opcode) in &self.dangerous_opcodes {
            let count = code.matches(opcode).count();
            
            if count > 0 {
                // Determine if this is likely a real opcode or just data
                let (is_suspicious, severity) = match *name {
                    "SELFDESTRUCT" => {
                        // FF is VERY common in data (0xFF, 0xFFFFFFFF, etc.)
                        // Only flag if count is very low (likely actual SELFDESTRUCT)
                        if count <= 2 && code_len < 5000 {
                            (true, Severity::Medium)
                        } else {
                            (false, Severity::Info) // Skip - likely data
                        }
                    }
                    "DELEGATECALL" => {
                        // F4 is less common, but still appears in data
                        // Flag if suspiciously many in small contract
                        if code_len < 1000 && count > 8 {
                            (true, Severity::High)
                        } else if count >= 2 && count <= 10 {
                            (true, Severity::Low)
                        } else if count > 30 {
                            (false, Severity::Info) // Too many - likely data
                        } else {
                            (false, Severity::Info)
                        }
                    }
                    "CALLCODE" => {
                        // F2 is deprecated and suspicious if actually used
                        // But also common in data
                        if count <= 2 && code_len < 5000 {
                            (true, Severity::Medium)
                        } else {
                            (false, Severity::Info)
                        }
                    }
                    _ => (false, Severity::Info),
                };
                
                // Only add finding if it's suspicious
                if is_suspicious {
                    findings.push(Finding {
                        severity,
                        category: Category::BytecodePattern,
                        message: format!("{} opcode found ({} occurrences)", name, count),
                        evidence: Some(serde_json::json!({
                            "opcode": opcode,
                            "count": count,
                            "bytecode_size": code_len
                        })),
                    });
                }
            }
        }
        
        findings
    }
    
    fn check_suspicious_combinations(&self, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Pattern 1: DELEGATECALL with SLOAD (delegatecall to storage-loaded address)
        let delegatecall_count = code.matches("F4").count();
        let sload_count = code.matches("54").count();
        
        // Only check if counts are reasonable (not excessive data noise)
        if delegatecall_count > 0 && delegatecall_count < 20 && sload_count > 0 && sload_count < 100 {
            // Check if they're close together (within 100 bytes)
            let delegatecall_positions: Vec<_> = code.match_indices("F4").map(|(i, _)| i).collect();
            let sload_positions: Vec<_> = code.match_indices("54").map(|(i, _)| i).collect();
            
            let mut close_proximity = false;
            for &dc_pos in delegatecall_positions.iter().take(10) {  // Only check first 10
                for &sl_pos in sload_positions.iter().take(20) {  // Only check first 20
                    if dc_pos.abs_diff(sl_pos) < 200 {
                        close_proximity = true;
                        break;
                    }
                }
                if close_proximity {
                    break;
                }
            }
            
            if close_proximity {
                findings.push(Finding {
                    severity: Severity::Medium,  // Reduced from High
                    category: Category::BytecodePattern,
                    message: "DELEGATECALL near SLOAD pattern detected".to_string(),
                    evidence: Some(serde_json::json!({
                        "description": "May use storage-loaded address (review implementation)"
                    })),
                });
            }
        }
        
        // Pattern 2: Contract size analysis
        let code_len = code.len() / 2;
        
        if code_len < 100 {
            findings.push(Finding {
                severity: Severity::High,
                category: Category::BytecodePattern,
                message: format!("Suspiciously small contract ({} bytes)", code_len),
                evidence: Some(serde_json::json!({
                    "description": "May be a minimal proxy or honeypot"
                })),
            });
        } else if code_len > 24576 {
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::BytecodePattern,
                message: "Contract exceeds maximum size limit".to_string(),
                evidence: Some(serde_json::json!({
                    "size": code_len,
                    "max_allowed": 24576
                })),
            });
        }
        
        // Pattern 3: Too many JUMPI (complex conditional logic)
        let jumpi_count = code.matches("57").count();
        
        // Only flag if truly excessive and contract is small
        if code_len < 2000 && jumpi_count > 100 {
            let jumpi_density = jumpi_count as f32 / (code_len as f32 / 100.0);
            
            findings.push(Finding {
                severity: Severity::Low,
                category: Category::BytecodePattern,
                message: format!("High conditional complexity ({} JUMPI instructions)", jumpi_count),
                evidence: Some(serde_json::json!({
                    "jumpi_count": jumpi_count,
                    "density": jumpi_density
                })),
            });
        }
        
        // Pattern 4: Check for hidden owner checks (CALLER followed by EQ)
        // Pattern: 33 (CALLER) 14 (EQ) - but be careful of false positives
        let caller_eq_count = code.matches("3314").count();
        
        if caller_eq_count > 8 && code_len < 3000 {
            findings.push(Finding {
                severity: Severity::Low,
                category: Category::BytecodePattern,
                message: format!("Multiple owner-like checks detected ({})", caller_eq_count),
                evidence: Some(serde_json::json!({
                    "pattern": "CALLER comparison pattern",
                    "count": caller_eq_count
                })),
            });
        }
        
        findings
    }
    
    fn severity_score(&self, severity: Severity) -> u32 {
        match severity {
            Severity::Critical => 50,
            Severity::High => 30,
            Severity::Medium => 15,
            Severity::Low => 5,
            Severity::Info => 0,
        }
    }
}

impl Default for StaticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Analyzer for StaticAnalyzer {
    fn name(&self) -> &'static str {
        "static-bytecode-analysis"
    }
    
    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
        let bytecode = target.bytecode.as_ref()
            .ok_or_else(|| crate::utils::DetectorError::AnalysisError(
                "Static analyzer requires bytecode".into()
            ))?;
        
        tracing::info!("Running static analysis on {} bytes", bytecode.len());
        
        let (findings, risk_score) = self.analyze_bytecode(bytecode);
        
        tracing::info!(
            "Static analysis complete: {} findings, risk score: {}", 
            findings.len(), 
            risk_score
        );
        
        Ok(AnalysisResult {
            risk_score,
            findings,
            metadata: std::collections::HashMap::new(),
        })
    }
    
    fn weight(&self) -> f64 {
        0.40  // 40% weight in ensemble (higher since it's deterministic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blacklist_detection() {
        let analyzer = StaticAnalyzer::new();
        
        // Bytecode with isBlacklisted selector
        let bytecode = hex::decode("FE575A87").unwrap();
        let (findings, score) = analyzer.analyze_bytecode(&bytecode);
        
        assert!(score > 0);
        assert!(findings.iter().any(|f| f.message.contains("Blacklist")));
    }
    
    #[test]
    fn test_missing_transfer() {
        let analyzer = StaticAnalyzer::new();
        
        // Bytecode without transfer() but with approve()
        let bytecode = hex::decode("095EA7B3").unwrap(); // Just approve()
        let (findings, score) = analyzer.analyze_bytecode(&bytecode);
        
        assert!(score > 50, "Should have high risk score");
        assert!(findings.iter().any(|f| f.message.contains("Missing transfer")));
    }
    
    #[test]
    fn test_safe_contract() {
        let analyzer = StaticAnalyzer::new();
        
        // Standard ERC20 functions
        let bytecode = hex::decode(
            "A9059CBB23B872DD095EA7B3" // transfer, transferFrom, approve
        ).unwrap();
        let (findings, score) = analyzer.analyze_bytecode(&bytecode);
        
        // Should have low risk
        assert!(score < 30, "Safe contract should have low risk score");
    }
}
