use super::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub risk_score: u8,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AnalysisResult {
    pub fn new(risk_score: u8) -> Self {
        Self {
            risk_score,
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }
    
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub address: String,
    pub is_honeypot: bool,
    pub risk_score: u8,
    pub confidence: f64,
    pub findings: Vec<Finding>,
    pub analyzer_results: HashMap<String, AnalysisResult>,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "═══════════════════════════════════════════════════════════")?;
        writeln!(f, "              HONEYPOT DETECTION REPORT")?;
        writeln!(f, "═══════════════════════════════════════════════════════════")?;
        writeln!(f)?;
        writeln!(f, "Address: {}", self.address)?;
        writeln!(f)?;
        writeln!(f, "═══ VERDICT ═══")?;
        
        let verdict_text = if self.is_honeypot {
            "🔴 HONEYPOT DETECTED"
        } else {
            "🟢 APPEARS SAFE"
        };
        
        writeln!(f, "{}", verdict_text)?;
        writeln!(f, "Risk Score: {}/100", self.risk_score)?;
        writeln!(f, "Confidence: {:.1}%", self.confidence * 100.0)?;
        
        if !self.findings.is_empty() {
            writeln!(f)?;
            writeln!(f, "═══ FINDINGS ═══")?;
            
            let mut sorted_findings = self.findings.clone();
            sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            
            for finding in sorted_findings.iter().take(10) {
                writeln!(f, "{} [{:?}] {}", 
                    finding.severity.emoji(),
                    finding.category,
                    finding.message
                )?;
            }
        }
        
        writeln!(f)?;
        writeln!(f, "═══════════════════════════════════════════════════════════")?;
        
        Ok(())
    }
}