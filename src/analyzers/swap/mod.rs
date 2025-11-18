//! Swap simulation for PulseX DEX
//! 
//! PHASE 3: Full buy/sell simulation with tax calculation and U112 overflow detection
//! PHASE 4: Approved holder simulation - RPC-only honeypot detection

mod types;
mod state_builder;
mod swap_tester;
mod holder_simulator;

pub use types::{SwapTest, SwapResult, SwapDirection, AdminRiskAnalysis, AdminRiskLevel};
pub use swap_tester::SwapSimulator;
pub use holder_simulator::{ApprovedHolderSimulator, ApprovedHolderVerdict, HolderSimResult, FailureType};

use ethers::types::U256;

/// Test amounts as percentages of liquidity
#[derive(Debug, Clone, Copy)]
pub struct TestAmounts {
    /// 0.01% of liquidity - micro test
    pub micro: U256,
    /// 1% of liquidity - typical user trade
    pub normal: U256,
    /// 5% of liquidity - whale trade
    pub large: U256,
}

impl TestAmounts {
    /// Calculate test amounts from liquidity
    pub fn from_liquidity(liquidity: U256) -> Self {
        Self {
            micro: liquidity / U256::from(10_000),     // 0.01%
            normal: liquidity / U256::from(100),       // 1%
            large: liquidity / U256::from(20),         // 5%
        }
    }
}
