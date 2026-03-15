pub mod static_analyzer;
pub mod simulator;
pub mod swap;  // PHASE 3: Swap simulation
pub mod mcp_client;
pub mod claude_analyzer;

#[cfg(feature = "ml-inference")]
pub mod ml_analyzer;

pub use static_analyzer::StaticAnalyzer;
pub use simulator::SimulatorAnalyzer;
pub use swap::{SwapSimulator, ApprovedHolderSimulator, ApprovedHolderVerdict, FailureType};  // PHASE 3 & 4
pub use mcp_client::{MCPClient, AnalysisMode, TokenUsage};
pub use claude_analyzer::ClaudeAnalyzer;

#[cfg(feature = "ml-inference")]
pub use ml_analyzer::MLAnalyzer;
