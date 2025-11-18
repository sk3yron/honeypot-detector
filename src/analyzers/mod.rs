pub mod static_analyzer;
pub mod simulator;
pub mod swap;  // PHASE 3: Swap simulation

#[cfg(feature = "ml-inference")]
pub mod ml_analyzer;

pub use static_analyzer::StaticAnalyzer;
pub use simulator::SimulatorAnalyzer;
pub use swap::{SwapSimulator, ApprovedHolderSimulator, ApprovedHolderVerdict, FailureType};  // PHASE 3 & 4

#[cfg(feature = "ml-inference")]
pub use ml_analyzer::MLAnalyzer;
