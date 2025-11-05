pub mod core;
pub mod models;
pub mod analyzers;
pub mod blockchain;
pub mod features;
pub mod utils;

pub use core::{Analyzer, HoneypotDetector};
pub use models::{ContractTarget, Verdict, Finding, Severity, Category};
pub use utils::{DetectorError, Result};