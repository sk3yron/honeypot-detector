use std::sync::Arc;
use crate::core::Analyzer;
use crate::models::{ContractTarget, Verdict, AnalysisResult};
use crate::utils::Result;
use std::collections::HashMap;

pub struct HoneypotDetector {
    analyzers: Vec<Arc<dyn Analyzer>>,
}

impl HoneypotDetector {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }
    
    pub fn add_analyzer(mut self, analyzer: Arc<dyn Analyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }
    
    /// Detect if a contract is a honeypot
    pub async fn detect(&self, target: ContractTarget) -> Result<Verdict> {
        let mut all_findings = Vec::new();
        let mut analyzer_results = HashMap::new();
        let mut weighted_score = 0.0;
        let mut total_weight = 0.0;
        
        // Run all analyzers
        for analyzer in &self.analyzers {
            if !analyzer.can_analyze(&target) {
                continue;
            }
            
            match analyzer.analyze(&target).await {
                Ok(result) => {
                    let weight = analyzer.weight();
                    weighted_score += result.risk_score as f64 * weight;
                    total_weight += weight;
                    
                    all_findings.extend(result.findings.clone());
                    analyzer_results.insert(analyzer.name().to_string(), result);
                }
                Err(e) => {
                    tracing::warn!("Analyzer '{}' failed: {}", analyzer.name(), e);
                }
            }
        }
        
        // Calculate final score
        let final_score = if total_weight > 0.0 {
            (weighted_score / total_weight) as u8
        } else {
            0
        };
        
        // Determine if honeypot
        let is_honeypot = final_score >= 60;
        
        // Calculate confidence based on analyzer agreement
        let confidence = self.calculate_confidence(&analyzer_results);
        
        Ok(Verdict {
            address: format!("{:?}", target.address),
            is_honeypot,
            risk_score: final_score,
            confidence,
            findings: all_findings,
            analyzer_results,
        })
    }
    
    fn calculate_confidence(&self, results: &HashMap<String, AnalysisResult>) -> f64 {
        if results.is_empty() {
            return 0.0;
        }
        
        let scores: Vec<u8> = results.values().map(|r| r.risk_score).collect();
        let mean = scores.iter().sum::<u8>() as f64 / scores.len() as f64;
        
        // Calculate variance
        let variance: f64 = scores.iter()
            .map(|&s| {
                let diff = s as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / scores.len() as f64;
        
        let std_dev = variance.sqrt();
        
        // Low std dev = high agreement = high confidence
        ((50.0 - std_dev.min(50.0)) / 50.0).clamp(0.0, 1.0)
    }
}

impl Default for HoneypotDetector {
    fn default() -> Self {
        Self::new()
    }
}