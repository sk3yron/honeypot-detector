use async_trait::async_trait;
use crate::models::{ContractTarget, AnalysisResult};
use crate::utils::Result;

/// Core abstraction: anything that analyzes a contract
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Unique identifier for this analyzer
    fn name(&self) -> &'static str;
    
    /// Analyze a contract and return findings
    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult>;
    
    /// Weight in ensemble voting (0.0 - 1.0)
    fn weight(&self) -> f64 {
        1.0
    }
    
    /// Can this analyzer run on this target?
    fn can_analyze(&self, _target: &ContractTarget) -> bool {
        true
    }
}