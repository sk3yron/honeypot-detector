pub mod static_analyzer;

#[cfg(feature = "ml-inference")]
pub mod ml_analyzer;

pub use static_analyzer::StaticAnalyzer;

#[cfg(feature = "ml-inference")]
pub use ml_analyzer::MLAnalyzer;
