//! Types for swap simulation

use ethers::types::{U256, Address};

/// Direction of swap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapDirection {
    /// Buy: PLS -> Token
    Buy,
    /// Sell: Token -> PLS
    Sell,
}

/// Result of a single swap test
#[derive(Debug, Clone)]
pub struct SwapResult {
    /// Whether the swap succeeded
    pub success: bool,
    
    /// Amount in
    pub amount_in: U256,
    
    /// Amount out received
    pub amount_out: U256,
    
    /// Gas used
    pub gas_used: u64,
    
    /// Revert reason if failed
    pub revert_reason: Option<String>,
    
    /// Calculated tax percentage (0-100)
    pub tax_percent: f64,
}

/// Complete swap test results for all amounts
#[derive(Debug, Clone)]
pub struct SwapTest {
    /// Buy test with 0.01% liquidity
    pub buy_micro: Option<SwapResult>,
    
    /// Buy test with 1% liquidity
    pub buy_normal: Option<SwapResult>,
    
    /// Buy test with 5% liquidity
    pub buy_large: Option<SwapResult>,
    
    /// Sell test with 0.01% liquidity
    pub sell_micro: Option<SwapResult>,
    
    /// Sell test with 1% liquidity
    pub sell_normal: Option<SwapResult>,
    
    /// Sell test with 5% liquidity
    pub sell_large: Option<SwapResult>,
    
    /// Average buy tax
    pub avg_buy_tax: f64,
    
    /// Average sell tax
    pub avg_sell_tax: f64,
    
    /// Whether U112 overflow detected
    pub has_overflow_trap: bool,
    
    /// Whether amount-dependent blocks detected
    pub has_amount_limits: bool,
}

impl SwapTest {
    /// Create empty test
    pub fn empty() -> Self {
        Self {
            buy_micro: None,
            buy_normal: None,
            buy_large: None,
            sell_micro: None,
            sell_normal: None,
            sell_large: None,
            avg_buy_tax: 0.0,
            avg_sell_tax: 0.0,
            has_overflow_trap: false,
            has_amount_limits: false,
        }
    }
    
    /// Check if all swaps succeeded
    pub fn all_success(&self) -> bool {
        self.buy_micro.as_ref().map(|r| r.success).unwrap_or(false)
            && self.buy_normal.as_ref().map(|r| r.success).unwrap_or(false)
            && self.sell_micro.as_ref().map(|r| r.success).unwrap_or(false)
            && self.sell_normal.as_ref().map(|r| r.success).unwrap_or(false)
    }
    
    /// Check if has suspicious patterns
    pub fn is_suspicious(&self) -> bool {
        self.has_overflow_trap
            || self.has_amount_limits
            || self.avg_buy_tax > 25.0
            || self.avg_sell_tax > 25.0
    }
}

/// Admin/Owner risk level for token contracts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRiskLevel {
    /// No admin functions detected
    None,
    /// Has admin functions but owner renounced
    Low,
    /// Has admin functions, owner active but limited privileges
    Medium,
    /// Has admin functions, owner active with dangerous privileges
    High,
    /// Multiple admin backdoors detected
    Critical,
}

impl AdminRiskLevel {
    pub fn description(&self) -> &'static str {
        match self {
            AdminRiskLevel::None => "No admin privileges",
            AdminRiskLevel::Low => "Admin functions exist but owner renounced",
            AdminRiskLevel::Medium => "Active owner with limited privileges",
            AdminRiskLevel::High => "Active owner with dangerous privileges",
            AdminRiskLevel::Critical => "Multiple admin backdoors - EXTREME RISK",
        }
    }
}

/// Analysis of admin/owner risks in token contract
#[derive(Debug, Clone)]
pub struct AdminRiskAnalysis {
    /// Whether contract has mint function
    pub has_mint: bool,
    
    /// Whether contract has burn function
    pub has_burn: bool,
    
    /// Whether contract has pause function
    pub has_pause: bool,
    
    /// Whether contract has blacklist function
    pub has_blacklist: bool,
    
    /// Whether contract has owner() function
    pub has_owner: bool,
    
    /// Owner address if detected
    pub owner_address: Option<Address>,
    
    /// Whether ownership is renounced (owner = 0x0 or 0xdead)
    pub is_renounced: bool,
    
    /// Overall risk level
    pub risk_level: AdminRiskLevel,
    
    /// Human-readable risk summary
    pub summary: String,
}

impl AdminRiskAnalysis {
    /// Create analysis with no risks
    pub fn none() -> Self {
        Self {
            has_mint: false,
            has_burn: false,
            has_pause: false,
            has_blacklist: false,
            has_owner: false,
            owner_address: None,
            is_renounced: false,
            risk_level: AdminRiskLevel::None,
            summary: "No admin privileges detected".to_string(),
        }
    }
    
    /// Calculate risk level based on detected functions
    pub fn calculate_risk_level(&mut self) {
        let dangerous_count = [
            self.has_mint,
            self.has_pause,
            self.has_blacklist,
        ].iter().filter(|&&x| x).count();
        
        if dangerous_count == 0 {
            self.risk_level = AdminRiskLevel::None;
            self.summary = "No admin privileges detected - Safe".to_string();
        } else if self.is_renounced {
            self.risk_level = AdminRiskLevel::Low;
            self.summary = format!(
                "Admin functions detected ({}) but owner renounced - Low risk",
                self.get_functions_list()
            );
        } else if dangerous_count >= 2 {
            self.risk_level = AdminRiskLevel::Critical;
            self.summary = format!(
                "⚠️ CRITICAL: Owner can {} - HIGH RUG RISK!",
                self.get_functions_list()
            );
        } else if self.has_mint || self.has_blacklist {
            self.risk_level = AdminRiskLevel::High;
            self.summary = format!(
                "⚠️ HIGH RISK: Owner can {} - Can prevent sells!",
                self.get_functions_list()
            );
        } else {
            self.risk_level = AdminRiskLevel::Medium;
            self.summary = format!(
                "⚠️ MEDIUM RISK: Owner has {} privileges",
                self.get_functions_list()
            );
        }
    }
    
    /// Get comma-separated list of detected functions
    fn get_functions_list(&self) -> String {
        let mut funcs = Vec::new();
        if self.has_mint { funcs.push("mint unlimited tokens"); }
        if self.has_burn { funcs.push("burn tokens"); }
        if self.has_pause { funcs.push("pause trading"); }
        if self.has_blacklist { funcs.push("blacklist addresses"); }
        
        if funcs.is_empty() {
            "unknown privileges".to_string()
        } else {
            funcs.join(", ")
        }
    }
}
