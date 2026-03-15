pub mod contracts;      // PulseX contract interfaces
pub mod storage;        // Storage layout detection
pub mod verification;   // Factory verification
pub mod pool_tracker;   // NEW - Pool tracking system

pub mod core;
pub mod models;
pub mod analyzers;
pub mod blockchain;
pub mod features;
pub mod utils;

pub use core::{Analyzer, HoneypotDetector};
pub use models::{ContractTarget, Verdict, Finding, Severity, Category};
pub use utils::{DetectorError, Result};
