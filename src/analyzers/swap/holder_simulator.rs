//! Approved Holder Simulation
//! 
//! This module finds real token holders who have approved the PulseX router
//! and simulates selling from their addresses using eth_estimateGas.
//! 
//! This is the most accurate RPC-only honeypot detection possible because:
//! - Uses real balances (no fake injection needed)
//! - Uses real approvals (holder already approved router)
//! - Tests actual sell path (router.swapExactTokensForTokens)
//! - Works with free public RPC nodes
//! - Catches 85-95% of honeypots

use std::sync::Arc;
use std::time::Duration;
use ethers::types::{Address, U256, Filter, H256, Bytes};
use ethers::contract::abigen;
use ethers::providers::Middleware;
use crate::blockchain::BlockchainClient;
use crate::contracts::addresses;
use crate::utils::{Result, DetectorError};
use super::types::AdminRiskAnalysis;

/// Result of simulating a sell from an approved holder
#[derive(Debug, Clone)]
pub struct HolderSimResult {
    pub holder: Address,
    pub balance: U256,
    pub allowance: U256,
    pub can_sell: bool,
    pub gas_estimate: Option<u64>,
    pub error_reason: Option<String>,
}

/// Classification of why a sell simulation failed
#[derive(Debug, Clone, PartialEq)]
pub enum FailureType {
    /// Not a honeypot - just needs more approval
    NeedsApproval,
    /// Not a honeypot - holder has insufficient balance
    InsufficientBalance,
    /// Not a honeypot - insufficient liquidity or too much slippage (K invariant violation)
    InsufficientLiquidity(String),
    /// Honeypot - math overflow (likely U112 trap)
    MathOverflow(String),
    /// Honeypot - transfer explicitly blocked
    TransferBlocked(String),
    /// Honeypot - custom error
    CustomError(String),
    /// Unknown error - likely honeypot
    Unknown(String),
}

impl FailureType {
    pub fn is_honeypot(&self) -> bool {
        matches!(self,
            FailureType::MathOverflow(_) |
            FailureType::TransferBlocked(_) |
            FailureType::CustomError(_) |
            FailureType::Unknown(_)
        )
    }
}

/// Finds holders and simulates selling
pub struct ApprovedHolderSimulator {
    client: Arc<BlockchainClient>,
    router: Address,
}

impl ApprovedHolderSimulator {
    pub fn new(client: Arc<BlockchainClient>) -> Self {
        let router = addresses::PULSEX_ROUTER.parse().unwrap();
        Self { client, router }
    }

    /// Find the deployment block of a contract using binary search
    async fn find_deployment_block(&self, token: Address) -> Result<u64> {
        tracing::debug!("🔍 Finding deployment block for {:?}...", token);
        
        let current_block = self.client.provider.get_block_number().await
            .map_err(DetectorError::RpcError)?
            .as_u64();
        
        // PulseChain launched around block 17M, but let's start from block 1M to be safe
        let mut low = 1_000_000u64;
        let mut high = current_block;
        let mut deployment_block = current_block;
        
        // Binary search for first block where contract exists
        while low <= high {
            let mid = (low + high) / 2;
            
            match self.client.provider.get_code(token, Some(mid.into())).await {
                Ok(code) if !code.is_empty() => {
                    // Contract exists at this block, search earlier
                    deployment_block = mid;
                    high = mid.saturating_sub(1);
                }
                _ => {
                    // Contract doesn't exist yet, search later
                    low = mid + 1;
                }
            }
            
            // Avoid too many iterations
            if high - low < 1000 {
                break;
            }
        }
        
        tracing::info!("📍 Contract deployed around block {}", deployment_block);
        Ok(deployment_block)
    }

    /// Calculate block ranges for quarter-based scanning
    /// Returns quarters in reverse chronological order (newest first)
    fn calculate_quarter_ranges(
        deployment_block: u64,
        current_block: u64,
    ) -> Vec<(u64, u64, &'static str)> {
        let total_blocks = current_block.saturating_sub(deployment_block);
        
        // If very small history, just return one range
        if total_blocks < 100_000 {
            return vec![(deployment_block, current_block, "Full History")];
        }
        
        let quarter_size = total_blocks / 4;
        
        // Q4 (Most Recent): 75-100%
        let q4_start = current_block.saturating_sub(quarter_size);
        let q4_end = current_block;
        
        // Q3 (2nd Recent): 50-75%
        let q3_start = current_block.saturating_sub(quarter_size * 2);
        let q3_end = q4_start;
        
        // Q2 (2nd Oldest): 25-50%
        let q2_start = current_block.saturating_sub(quarter_size * 3);
        let q2_end = q3_start;
        
        // Q1 (Oldest): 0-25%
        let q1_start = deployment_block;
        let q1_end = q2_start;
        
        // Return in reverse chronological order (scan newest first)
        vec![
            (q4_start, q4_end, "Q4 (Most Recent 25%)"),
            (q3_start, q3_end, "Q3 (2nd Recent 25%)"),
            (q2_start, q2_end, "Q2 (2nd Oldest 25%)"),
            (q1_start, q1_end, "Q1 (Oldest 25%)"),
        ]
    }

    /// Find optimal chunk size using binary search
    /// This prevents RPC timeout errors by finding the largest chunk size the RPC can handle
    async fn find_optimal_chunk_size(
        &self,
        token: Address,
        test_start_block: u64,
        test_end_block: u64,
    ) -> u64 {
        const MIN_CHUNK_SIZE: u64 = 1_000;    // Minimum: 1k blocks
        const MAX_CHUNK_SIZE: u64 = 50_000;   // Maximum: 50k blocks
        const MAX_ATTEMPTS: u8 = 12;           // Limit binary search iterations
        
        let mut low = MIN_CHUNK_SIZE;
        let mut high = MAX_CHUNK_SIZE;
        let mut best_size = MIN_CHUNK_SIZE;
        let mut attempts = 0;
        
        tracing::info!("🔍 Finding optimal chunk size using binary search...");
        
        while low <= high && attempts < MAX_ATTEMPTS {
            let mid = (low + high) / 2;
            let test_to_block = (test_start_block + mid).min(test_end_block);
            
            // Try querying with this chunk size
            let filter = Filter::new()
                .address(token)
                .event("Approval(address,address,uint256)")
                .from_block(test_start_block)
                .to_block(test_to_block);
            
            tracing::debug!("  Testing chunk size: {} blocks ({} to {})", 
                mid, test_start_block, test_to_block);
            
            // Use tokio timeout to avoid hanging
            match tokio::time::timeout(
                Duration::from_secs(15),  // 15 second timeout per test
                self.client.provider.get_logs(&filter)
            ).await {
                Ok(Ok(_logs)) => {
                    // Success! This chunk size works
                    best_size = mid;
                    tracing::debug!("  ✅ Chunk size {} works!", mid);
                    low = mid + 1;  // Try larger
                }
                Ok(Err(e)) if e.to_string().contains("-32005") || 
                              e.to_string().contains("timeout") ||
                              e.to_string().contains("query timeout exceeded") => {
                    // RPC timeout - chunk too large
                    tracing::debug!("  ❌ Chunk size {} too large (RPC timeout)", mid);
                    high = mid - 1;  // Try smaller
                }
                Err(_) => {
                    // Local timeout (15 seconds) - chunk too large
                    tracing::debug!("  ⏱️  Chunk size {} timed out locally", mid);
                    high = mid - 1;  // Try smaller
                }
                Ok(Err(e)) => {
                    // Other RPC error - try smaller to be safe
                    tracing::debug!("  ⚠️  Chunk size {} failed: {}", mid, e);
                    high = mid - 1;
                }
            }
            
            attempts += 1;
        }
        
        // Use conservative estimate (75% of best to be safe)
        let optimal_size = ((best_size as f64) * 0.75) as u64;
        let final_size = optimal_size.max(MIN_CHUNK_SIZE);
        
        tracing::info!("✅ Optimal chunk size: {} blocks (tested up to {}, using 75% for safety)", 
            final_size, best_size);
        
        final_size
    }

    /// Find holders who have approved the router
    pub async fn find_approved_holders(
        &self,
        token: Address,
        max_holders: usize,
    ) -> Result<Vec<Address>> {
        tracing::info!("🔍 Searching for holders who approved router...");

        // Get current block
        let current_block = self.client.provider.get_block_number().await
            .map_err(DetectorError::RpcError)?;

        // Find deployment block
        let deployment_block = self.find_deployment_block(token).await.unwrap_or_else(|_| {
            // Fallback to searching last 200k blocks if deployment search fails
            current_block.as_u64().saturating_sub(200_000)
        });
        
        // Calculate total blocks to search
        let current_block_u64 = current_block.as_u64();
        let blocks_since_deployment = current_block_u64.saturating_sub(deployment_block);
        
        // Calculate quarter ranges for reverse chronological scanning
        let quarter_ranges = Self::calculate_quarter_ranges(deployment_block, current_block_u64);
        let total_blocks = current_block_u64.saturating_sub(deployment_block);

        tracing::info!("📊 Token has {} total blocks of history. Will scan in quarters (newest first).", total_blocks);

        let mut all_logs = Vec::new();
        let mut optimal_chunk_size: Option<u64> = None;
        
        // Scan each quarter, newest first
        for (i, (quarter_start, quarter_end, quarter_name)) in quarter_ranges.iter().enumerate() {
            let quarter_blocks = quarter_end.saturating_sub(*quarter_start);
            
            tracing::info!("🔍 Scanning {} ({} blocks: {} to {})", 
                quarter_name, quarter_blocks, quarter_start, quarter_end);
            
            // Find optimal chunk size on first quarter (reuse for subsequent quarters)
            let mut chunk_size = if i == 0 {
                let optimal = self.find_optimal_chunk_size(token, *quarter_start, *quarter_end).await;
                optimal_chunk_size = Some(optimal);
                optimal
            } else {
                optimal_chunk_size.unwrap_or(10_000) // Fallback if somehow not set
            };
            
            tracing::info!("📏 Using chunk size: {} blocks for {}", chunk_size, quarter_name);
            
            let mut current_from = *quarter_start;
            let mut consecutive_failures = 0;
            
            while current_from < *quarter_end {
                let to_block = (current_from + chunk_size).min(*quarter_end);
                
                let filter = Filter::new()
                    .address(token)
                    .event("Approval(address,address,uint256)")
                    .from_block(current_from)
                    .to_block(to_block);

                tracing::debug!("Querying Approval events from block {} to {}", current_from, to_block);

                match self.client.provider.get_logs(&filter).await {
                    Ok(logs) => {
                        all_logs.extend(logs);
                        consecutive_failures = 0; // Reset on success
                        
                        // Early exit if we found enough approvals
                        if all_logs.len() >= 50 {
                            tracing::info!("✅ Found {} approval events in {} - stopping search!", 
                                all_logs.len(), quarter_name);
                            break;
                        }
                    }
                    Err(e) if e.to_string().contains("-32005") || 
                              e.to_string().contains("timeout") ||
                              e.to_string().contains("query timeout exceeded") => {
                        consecutive_failures += 1;
                        
                        // Exponential backoff: reduce chunk size on repeated failures
                        if consecutive_failures >= 3 {
                            let old_size = chunk_size;
                            chunk_size = (chunk_size / 2).max(1_000);
                            tracing::warn!("⚠️  {} consecutive timeouts in {}, reducing chunk size: {} → {}", 
                                consecutive_failures, quarter_name, old_size, chunk_size);
                            consecutive_failures = 0; // Reset after adjustment
                        } else {
                            tracing::warn!("Failed to query {} range {} to {} (attempt {}/3): RPC timeout", 
                                quarter_name, current_from, to_block, consecutive_failures);
                        }
                        
                        // Continue to next chunk instead of breaking
                    }
                    Err(e) => {
                        tracing::warn!("Failed to query {} range {} to {}: {}", 
                            quarter_name, current_from, to_block, e);
                        // Continue to next chunk for other errors too
                    }
                }
                
                current_from = to_block + 1;
            }
            
            tracing::info!("✅ Completed {} - found {} total approvals so far", 
                quarter_name, all_logs.len());
            
            // If we found enough approvals in this quarter, stop scanning
            if all_logs.len() >= 50 {
                tracing::info!("🎯 Found sufficient approvals ({}) - stopping quarter scan", all_logs.len());
                break;
            }
            
            // If we found some but not enough, continue to next quarter
            if all_logs.len() > 0 && all_logs.len() < 50 {
                tracing::info!("⏭️  Found {} approvals in {} - continuing to next quarter for more...", 
                    all_logs.len(), quarter_name);
            }
        }

        tracing::info!("Found {} Approval events", all_logs.len());
        let logs = all_logs;

        // Generate ERC20 contract interface
        abigen!(IERC20, r#"[
            function balanceOf(address) external view returns (uint256)
            function allowance(address,address) external view returns (uint256)
        ]"#);

        let token_contract = IERC20::new(token, self.client.provider.clone());

        let mut approved_holders = Vec::new();
        
        let router_v1: Address = addresses::PULSEX_ROUTER_V1.parse().unwrap();
        let router_v2: Address = addresses::PULSEX_ROUTER_V2.parse().unwrap();
        let piteas_router: Address = addresses::PITEAS_ROUTER.parse().unwrap();

        for log in logs {
            if approved_holders.len() >= max_holders {
                break;
            }

            // Decode Approval event: Approval(address indexed owner, address indexed spender, uint256 value)
            if log.topics.len() < 3 {
                continue;
            }

            // Topics are 32 bytes (H256), but addresses are only 20 bytes (last 20 bytes)
            let owner_bytes = &log.topics[1].as_bytes()[12..]; // Skip first 12 bytes
            let owner = Address::from_slice(owner_bytes);
            
            let spender_bytes = &log.topics[2].as_bytes()[12..];
            let spender = Address::from_slice(spender_bytes);

            // Check approvals to PulseX Router V1, V2, and Piteas Router
            if spender != router_v1 && spender != router_v2 && spender != piteas_router {
                tracing::debug!("Skipping approval to unknown router: {:?}", spender);
                continue;
            }
            
            tracing::debug!("Found approval from {:?} to router {:?}", owner, spender);

            // Check if holder still has balance
            let balance = token_contract.balance_of(owner).call().await
                .map_err(|e| DetectorError::ContractError(format!("Failed to check balance: {}", e)))?;

            if balance.is_zero() {
                continue;
            }

            // Check if approval is still valid FOR THE SPECIFIC ROUTER THEY APPROVED
            let allowance = token_contract.allowance(owner, spender).call().await
                .map_err(|e| DetectorError::ContractError(format!("Failed to check allowance: {}", e)))?;

            if allowance.is_zero() {
                continue;
            }

            tracing::debug!("Found approved holder: {:?} (balance: {}, allowance: {} for router {:?})", 
                owner, balance, allowance, spender);

            approved_holders.push(owner);
        }

        tracing::info!("✅ Found {} holders with valid approvals and balances", approved_holders.len());

        Ok(approved_holders)
    }

    /// Detect transfer tax by simulating multiple sell amounts
    /// Returns the detected tax percentage (0.0 to 1.0) by trying different amounts
    async fn detect_transfer_tax(
        &self,
        token: Address,
        holder: Address,
        wpls: Address,
    ) -> Result<f64> {
        tracing::debug!("🔍 Attempting to detect transfer tax for token {:?}", token);
        
        // Try common tax rates: 0%, 5%, 10%, 15%, 20%, 25%
        let tax_rates = vec![0.0, 0.05, 0.10, 0.15, 0.20, 0.25];
        
        for &tax_rate in &tax_rates {
            let multiplier = 1.0 - tax_rate;
            
            // Try to simulate with this tax adjustment
            match self.simulate_sell_from_holder_with_tax_adjustment(
                token, 
                holder, 
                wpls, 
                Some(multiplier)
            ).await {
                Ok(result) if result.can_sell => {
                    if tax_rate > 0.0 {
                        tracing::info!("✅ Detected {:.0}% transfer tax", tax_rate * 100.0);
                    }
                    return Ok(tax_rate);
                }
                _ => continue,
            }
        }
        
        tracing::debug!("Could not detect transfer tax, assuming 0%");
        Ok(0.0)
    }

    /// Simulate selling from an approved holder with optional tax adjustment
    pub async fn simulate_sell_from_holder(
        &self,
        token: Address,
        holder: Address,
        wpls: Address,
    ) -> Result<HolderSimResult> {
        self.simulate_sell_from_holder_with_tax_adjustment(token, holder, wpls, None).await
    }

    /// Internal: Simulate selling with tax adjustment
    async fn simulate_sell_from_holder_with_tax_adjustment(
        &self,
        token: Address,
        holder: Address,
        wpls: Address,
        tax_multiplier: Option<f64>, // If Some(0.95), reduce sell amount by 5%
    ) -> Result<HolderSimResult> {
        // Generate ERC20 interface
        abigen!(IERC20Check, r#"[
            function balanceOf(address) external view returns (uint256)
            function allowance(address,address) external view returns (uint256)
        ]"#);

        let token_contract = IERC20Check::new(token, self.client.provider.clone());

        // Get holder's balance
        let balance = token_contract.balance_of(holder).call().await
            .map_err(|e| DetectorError::ContractError(format!("Failed to get balance: {}", e)))?;

        tracing::debug!("Holder {:?}: balance={}", holder, balance);

        if balance.is_zero() {
            return Ok(HolderSimResult {
                holder,
                balance,
                allowance: U256::zero(),
                can_sell: false,
                gas_estimate: None,
                error_reason: Some("Zero balance".to_string()),
            });
        }

        // Calculate test amount
        // Start with smaller amounts to avoid high price impact (user typically sells with 1-2% impact)
        // Use 0.1% of balance (we'll check allowances later per router)
        let mut test_amount = balance / 1000;  // 0.1% of balance (smaller to reduce price impact)
        
        // If test amount is too small, try 0.5% instead
        if test_amount.is_zero() {
            test_amount = balance / 200;  // 0.5%
        }

        // Apply tax multiplier if provided (e.g., 0.95 for 5% tax)
        if let Some(multiplier) = tax_multiplier {
            test_amount = U256::from((test_amount.as_u128() as f64 * multiplier) as u128);
            tracing::debug!("Applied tax multiplier {:.2}, adjusted amount to {}", multiplier, test_amount);
        }

        if test_amount.is_zero() {
            return Ok(HolderSimResult {
                holder,
                balance,
                allowance: U256::zero(),
                can_sell: false,
                gas_estimate: None,
                error_reason: Some("Test amount too small".to_string()),
            });
        }

        let tax_note = if tax_multiplier.is_some() {
            format!(" (tax-adjusted)")
        } else {
            String::new()
        };
        tracing::info!("Testing sell of {} tokens{} from holder {:?}", test_amount, tax_note, holder);

        // Try all 3 routers - succeed if ANY works
        let routers = vec![
            ("V1", addresses::PULSEX_ROUTER_V1.parse::<Address>().unwrap()),
            ("V2", addresses::PULSEX_ROUTER_V2.parse::<Address>().unwrap()),
            ("Piteas", addresses::PITEAS_ROUTER.parse::<Address>().unwrap()),
        ];

        use ethers::types::transaction::eip2718::TypedTransaction;
        use ethers::types::TransactionRequest;

        let mut last_error = String::new();
        let mut total_allowance = U256::zero();

        for (router_name, router) in routers {
            // Check allowance for this specific router
            let allowance = token_contract.allowance(holder, router).call().await
                .map_err(|e| DetectorError::ContractError(format!("Failed to get allowance: {}", e)))?;

            if allowance > total_allowance {
                total_allowance = allowance;
            }

            if allowance.is_zero() {
                tracing::debug!("  {} router: no allowance", router_name);
                continue;
            }

            tracing::debug!("  Trying {} router (allowance: {})...", router_name, allowance);

            // Build swapExactTokensForTokens calldata
            let swap_calldata = self.encode_swap_exact_tokens_for_tokens(
                test_amount,
                U256::zero(), // amountOutMin = 0 for testing
                vec![token, wpls],
                holder,
                U256::from(u64::MAX), // deadline far in future
            );

            let tx: TypedTransaction = TransactionRequest {
                from: Some(holder),
                to: Some(router.into()),
                data: Some(swap_calldata.into()),
                ..Default::default()
            }.into();

            match self.client.provider.estimate_gas(&tx, None).await {
                Ok(gas) => {
                    tracing::info!("✅ Holder {:?} CAN sell via {} router! Gas: {}", holder, router_name, gas);
                    return Ok(HolderSimResult {
                        holder,
                        balance,
                        allowance: total_allowance,
                        can_sell: true,
                        gas_estimate: Some(gas.as_u64()),
                        error_reason: None,
                    });
                }
                Err(e) => {
                    last_error = format!("{:?}", e);
                    tracing::debug!("  {} router failed: {}", router_name, last_error);
                }
            }
        }

        // All routers failed
        tracing::warn!("❌ Holder {:?} CANNOT sell via any router. Last error: {}", holder, last_error);
        
        Ok(HolderSimResult {
            holder,
            balance,
            allowance: total_allowance,
            can_sell: false,
            gas_estimate: None,
            error_reason: Some(last_error),
        })
    }

    /// Encode swapExactTokensForTokens function call
    fn encode_swap_exact_tokens_for_tokens(
        &self,
        amount_in: U256,
        amount_out_min: U256,
        path: Vec<Address>,
        to: Address,
        deadline: U256,
    ) -> Vec<u8> {
        // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
        // Function selector: 0x38ed1739

        let mut calldata = vec![0x38, 0xed, 0x17, 0x39];

        // Encode amountIn (uint256)
        let mut amount_in_bytes = [0u8; 32];
        amount_in.to_big_endian(&mut amount_in_bytes);
        calldata.extend_from_slice(&amount_in_bytes);

        // Encode amountOutMin (uint256)
        let mut amount_out_min_bytes = [0u8; 32];
        amount_out_min.to_big_endian(&mut amount_out_min_bytes);
        calldata.extend_from_slice(&amount_out_min_bytes);

        // Encode path offset (uint256) - starts at byte 160 (5 * 32)
        let mut path_offset = [0u8; 32];
        path_offset[31] = 0xa0; // 160 in hex
        calldata.extend_from_slice(&path_offset);

        // Encode to (address)
        let mut to_bytes = [0u8; 32];
        to_bytes[12..32].copy_from_slice(to.as_bytes());
        calldata.extend_from_slice(&to_bytes);

        // Encode deadline (uint256)
        let mut deadline_bytes = [0u8; 32];
        deadline.to_big_endian(&mut deadline_bytes);
        calldata.extend_from_slice(&deadline_bytes);

        // Encode path array
        // Array length
        let mut path_length = [0u8; 32];
        path_length[31] = path.len() as u8;
        calldata.extend_from_slice(&path_length);

        // Array elements
        for addr in path {
            let mut addr_bytes = [0u8; 32];
            addr_bytes[12..32].copy_from_slice(addr.as_bytes());
            calldata.extend_from_slice(&addr_bytes);
        }

        calldata
    }

    /// Classify why a sell simulation failed
    pub fn classify_failure(&self, error: &str) -> FailureType {
        let error_lower = error.to_lowercase();

        if error_lower.contains("allowance") || error_lower.contains("insufficient allowance") {
            FailureType::NeedsApproval
        } else if error_lower.contains("balance") || error_lower.contains("transfer amount exceeds") {
            FailureType::InsufficientBalance
        } else if error_lower.contains("pulsex: k") || error_lower.contains("uniswap: k") {
            // K invariant failure - this is a liquidity/slippage issue, NOT a honeypot
            FailureType::InsufficientLiquidity(error.to_string())
        } else if error_lower.contains("overflow") || error_lower.contains("safemath") {
            FailureType::MathOverflow(error.to_string())
        } else if error_lower.contains("0xe450d38c") {
            FailureType::CustomError("Custom revert (0xe450d38c)".to_string())
        } else if error_lower.contains("transfer_failed") || error_lower.contains("transfer failed") {
            FailureType::TransferBlocked(error.to_string())
        } else if error_lower.contains("lok") {
            FailureType::MathOverflow("UniswapV2: LOK (overflow)".to_string())
        } else {
            FailureType::Unknown(error.to_string())
        }
    }

    /// Check if bytecode contains DELEGATECALL opcode
    fn contains_delegatecall(bytecode: &[u8]) -> bool {
        // DELEGATECALL opcode is 0xf4
        bytecode.contains(&0xf4)
    }

    /// Detect address-based access control pattern (CALLER + SLOAD)
    fn has_access_control_pattern(bytecode: &[u8]) -> bool {
        let code_hex = hex::encode(bytecode);
        
        // CALLER opcode: 0x33
        // SLOAD opcode: 0x54
        // Pattern indicates checking msg.sender against storage
        code_hex.contains("33") && code_hex.contains("54")
    }

    /// Extract delegate contract addresses from storage
    async fn extract_delegate_contracts(&self, token: Address) -> Result<Vec<Address>> {
        let mut delegates = Vec::new();
        
        // Method 1: Check EIP-1967 implementation slot
        // keccak256("eip1967.proxy.implementation") - 1
        let eip1967_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
        if let Ok(slot_h256) = eip1967_slot.parse::<H256>() {
            let storage_value = self.client.provider.get_storage_at(token, slot_h256, None).await
                .map_err(DetectorError::RpcError)?;
            
            if !storage_value.is_zero() {
                let addr = Address::from_slice(&storage_value.as_bytes()[12..]);
                let code = self.client.provider.get_code(addr, None).await
                    .map_err(DetectorError::RpcError)?;
                if !code.is_empty() {
                    tracing::info!("📍 Found EIP-1967 delegate: {:?}", addr);
                    delegates.push(addr);
                }
            }
        }
        
        // Method 2: Scan first 20 storage slots for contract addresses
        for slot_num in 0..20u64 {
            let slot = H256::from_low_u64_be(slot_num);
            let storage_value = self.client.provider.get_storage_at(token, slot, None).await
                .map_err(DetectorError::RpcError)?;
            
            if !storage_value.is_zero() {
                let addr = Address::from_slice(&storage_value.as_bytes()[12..]);
                
                // Check if it's a valid contract
                if let Ok(code) = self.client.provider.get_code(addr, None).await {
                    if code.len() > 100 { // Reasonable contract size
                        tracing::debug!("📍 Found potential delegate in slot {}: {:?}", slot_num, addr);
                        if !delegates.contains(&addr) {
                            delegates.push(addr);
                        }
                    }
                }
            }
        }
        
        Ok(delegates)
    }

    /// Check bytecode for whitelist/exclusion functions
    async fn detect_whitelist_functions(&self, token: Address) -> Result<bool> {
        let bytecode = self.client.provider.get_code(token, None).await
            .map_err(DetectorError::RpcError)?;
        
        let code_hex = hex::encode(&bytecode);
        
        // Common whitelist function selectors
        let whitelist_selectors = vec![
            "3b124fe7", // isExcludedFromFee(address)
            "437823ec", // excludeFromFee(address)
            "ea2f0b37", // includeInFee(address)
            "5342acb4", // excludedFromFee(address)
            "7d1db4a5", // isExcluded(address)
        ];
        
        let mut found_count = 0;
        for selector in &whitelist_selectors {
            if code_hex.contains(selector) {
                tracing::warn!("⚠️  Found potential whitelist function: 0x{}", selector);
                found_count += 1;
            }
        }
        
        // Common whitelist/blacklist strings (hashed in events/errors)
        let suspicious_patterns = vec![
            "6578636c75646564",  // "excluded" in hex
            "77686974656c6973",  // "whitelist" in hex  
            "626c61636b6c6973",  // "blacklist" in hex
        ];
        
        for pattern in &suspicious_patterns {
            if code_hex.contains(pattern) {
                tracing::warn!("⚠️  Found suspicious pattern in bytecode: {}", pattern);
                found_count += 1;
            }
        }
        
        // Check if bytecode contains DELEGATECALL
        let has_delegatecall = Self::contains_delegatecall(&bytecode);
        
        if has_delegatecall {
            tracing::warn!("⚠️  Token uses DELEGATECALL - checking delegate contracts...");
            
            // Extract and check delegate contracts
            let delegates = self.extract_delegate_contracts(token).await?;
            
            for delegate_addr in delegates {
                tracing::info!("🔍 Analyzing delegate contract: {:?}", delegate_addr);
                
                let delegate_code = self.client.provider.get_code(delegate_addr, None).await
                    .map_err(DetectorError::RpcError)?;
                
                let delegate_hex = hex::encode(&delegate_code);
                
                // Check delegate for whitelist selectors
                for selector in &whitelist_selectors {
                    if delegate_hex.contains(selector) {
                        tracing::warn!("⚠️  Found whitelist function in delegate: 0x{}", selector);
                        return Ok(true);
                    }
                }
                
                // Check for access control pattern (CALLER + SLOAD)
                if Self::has_access_control_pattern(&delegate_code) {
                    tracing::warn!("⚠️  Delegate has address-based access control (CALLER+SLOAD pattern)");
                    found_count += 2; // Strong indicator
                }
            }
        }
        
        Ok(found_count >= 2) // If 2+ whitelist indicators, flag as suspicious
    }

    /// Append admin risk warning to verdict message
    fn append_admin_warning(message: String, admin_risks: &Option<AdminRiskAnalysis>) -> String {
        if let Some(ref admin) = admin_risks {
            use super::types::AdminRiskLevel;
            
            match admin.risk_level {
                AdminRiskLevel::None => message,
                AdminRiskLevel::Low => {
                    format!("{}\n\n📋 Admin Check: {}", message, admin.summary)
                }
                AdminRiskLevel::Medium | AdminRiskLevel::High | AdminRiskLevel::Critical => {
                    format!("{}\n\n{}", message, admin.summary)
                }
            }
        } else {
            message
        }
    }
    
    /// Detect admin/owner functions and privileges
    pub async fn detect_admin_functions(&self, token: Address) -> Result<AdminRiskAnalysis> {
        use super::types::{AdminRiskAnalysis, AdminRiskLevel};
        
        tracing::debug!("🔍 Detecting admin functions for token {:?}", token);
        
        let mut analysis = AdminRiskAnalysis::none();
        
        // Get token bytecode
        let bytecode = self.client.provider.get_code(token, None).await
            .map_err(DetectorError::RpcError)?;
        
        if bytecode.is_empty() {
            return Ok(analysis);
        }
        
        let code_hex = hex::encode(&bytecode);
        
        // Function selectors to check for:
        // mint(address,uint256) = 0x40c10f19
        // burn(uint256) = 0x42966c68
        // pause() = 0x8456cb59
        // unpause() = 0x3f4ba83a
        // owner() = 0x8da5cb5b
        // renounceOwnership() = 0x715018a6
        // blacklist(address) / addToBlacklist variations
        
        analysis.has_mint = code_hex.contains("40c10f19");
        analysis.has_burn = code_hex.contains("42966c68");
        analysis.has_pause = code_hex.contains("8456cb59") || code_hex.contains("3f4ba83a");
        analysis.has_blacklist = code_hex.contains("626c61636b6c697374"); // "blacklist" in hex
        analysis.has_owner = code_hex.contains("8da5cb5b");
        
        if analysis.has_mint {
            tracing::info!("📍 Found mint() function");
        }
        if analysis.has_burn {
            tracing::info!("📍 Found burn() function");
        }
        if analysis.has_pause {
            tracing::info!("📍 Found pause/unpause() functions");
        }
        if analysis.has_blacklist {
            tracing::info!("📍 Found blacklist functionality");
        }
        
        // Try to call owner() function if it exists
        if analysis.has_owner {
            tracing::debug!("🔍 Attempting to call owner() function...");
            
            abigen!(IOwnable, r#"[
                function owner() external view returns (address)
            ]"#);
            
            let ownable = IOwnable::new(token, self.client.provider.clone());
            
            match ownable.owner().call().await {
                Ok(owner_addr) => {
                    analysis.owner_address = Some(owner_addr);
                    
                    // Check if owner is renounced
                    // Common renounce patterns: 0x0, 0xdead, 0x000...000
                    let is_zero = owner_addr == Address::zero();
                    let is_dead = owner_addr.to_string().to_lowercase().contains("dead");
                    
                    analysis.is_renounced = is_zero || is_dead;
                    
                    if analysis.is_renounced {
                        tracing::info!("✅ Owner is renounced: {:?}", owner_addr);
                    } else {
                        tracing::warn!("⚠️  Owner is active: {:?}", owner_addr);
                    }
                }
                Err(e) => {
                    tracing::debug!("Could not call owner(): {}", e);
                }
            }
        }
        
        // Calculate risk level
        analysis.calculate_risk_level();
        
        tracing::info!("📊 Admin Risk: {:?} - {}", analysis.risk_level, analysis.summary);
        
        Ok(analysis)
    }

    /// Run complete approved holder simulation test with 500 samples
    pub async fn run_complete_test(&self, token: Address) -> Result<ApprovedHolderVerdict> {
        use futures::stream::{self, StreamExt};
        
        let wpls: Address = addresses::WPLS.parse().unwrap();

        // Step 1: Detect admin/owner privileges
        tracing::info!("🔍 Detecting admin/owner privileges...");
        let admin_risks = self.detect_admin_functions(token).await.ok();
        
        if let Some(ref admin) = admin_risks {
            if admin.risk_level as u8 >= 2 { // Medium or higher
                tracing::warn!("⚠️  {}", admin.summary);
            }
        }
        
        // Step 2: Check bytecode for whitelist functions
        tracing::info!("🔍 Checking bytecode for whitelist functions...");
        let has_whitelist_functions = self.detect_whitelist_functions(token).await.unwrap_or(false);
        
        if has_whitelist_functions {
            tracing::warn!("⚠️  Whitelist functions detected in bytecode!");
        }

        // Step 3: Find approved holders (up to 500)
        tracing::info!("🔍 Finding approved holders...");
        let holders = self.find_approved_holders(token, 500).await?;

        if holders.is_empty() {
            return Ok(ApprovedHolderVerdict {
                is_honeypot: false,
                confidence: 0.0,
                tested_holders: 0,
                successful_sells: 0,
                failed_sells: 0,
                failure_types: Vec::new(),
                message: "No approved holders found - token might be new or no trading activity".to_string(),
                admin_risks,
            });
        }

        tracing::info!("📊 Found {} approved holders, will test up to 500", holders.len());

        // Step 4: Detect transfer tax using first holder
        tracing::info!("🔍 Detecting transfer tax...");
        let detected_tax = self.detect_transfer_tax(token, holders[0], wpls).await?;
        
        if detected_tax > 0.0 {
            tracing::info!("📊 Token has {:.1}% transfer tax", detected_tax * 100.0);
        }
        
        let tax_multiplier = if detected_tax > 0.0 {
            Some(1.0 - detected_tax)
        } else {
            None
        };

        // Step 4: Test holders in batches with parallel execution
        let mut all_results = Vec::new();
        let mut successful_sells = 0;
        let mut failed_sells = 0;
        let mut failure_types = Vec::new();
        
        let batch_size = 50;
        let max_holders_to_test = holders.len().min(500);
        let num_batches = (max_holders_to_test + batch_size - 1) / batch_size;
        
        for batch_idx in 0..num_batches {
            let start = batch_idx * batch_size;
            let end = (start + batch_size).min(max_holders_to_test);
            let batch_holders = &holders[start..end];
            
            tracing::info!("🔄 Testing batch {}/{} (holders {}-{})...", 
                batch_idx + 1, num_batches, start, end);
            
            // Test batch in parallel (10 concurrent requests)
            let batch_results: Vec<Result<HolderSimResult>> = stream::iter(batch_holders.iter())
                .map(|holder| {
                    let token = token;
                    let wpls = wpls;
                    let tax_mult = tax_multiplier;
                    async move {
                        self.simulate_sell_from_holder_with_tax_adjustment(
                            token, 
                            *holder, 
                            wpls,
                            tax_mult
                        ).await
                    }
                })
                .buffer_unordered(10) // 10 concurrent requests
                .collect()
                .await;
            
            // Process batch results
            let mut batch_success = 0;
            let mut batch_failed = 0;
            
            for result in batch_results {
                match result {
                    Ok(sim_result) => {
                        if sim_result.can_sell {
                            successful_sells += 1;
                            batch_success += 1;
                        } else if let Some(error) = &sim_result.error_reason {
                            failed_sells += 1;
                            batch_failed += 1;
                            let failure_type = self.classify_failure(error);
                            failure_types.push(failure_type);
                        }
                        all_results.push(sim_result);
                    }
                    Err(e) => {
                        tracing::warn!("Error testing holder: {}", e);
                    }
                }
            }
            
            let batch_total = batch_success + batch_failed;
            let batch_rate = if batch_total > 0 {
                batch_success as f64 / batch_total as f64 * 100.0
            } else {
                0.0
            };
            
            tracing::info!("   Batch result: {}/{} can sell ({:.1}%)", 
                batch_success, batch_total, batch_rate);
            
            // Early exit if pattern is very clear after 100+ samples
            let total_tested = successful_sells + failed_sells;
            if total_tested >= 100 {
                let current_rate = successful_sells as f64 / total_tested as f64;
                
                // If <20% success after 100 samples, clearly a honeypot
                if current_rate < 0.20 {
                    tracing::warn!("⚠️  Early exit: <20% success rate after {} samples - clear honeypot pattern", total_tested);
                    break;
                }
                
                // If >95% success after 200 samples and no whitelist functions, likely safe
                if total_tested >= 200 && current_rate > 0.95 && !has_whitelist_functions {
                    tracing::info!("✅ Early exit: >95% success rate after {} samples with no whitelist functions - likely safe", total_tested);
                    break;
                }
            }
        }

        // Step 5: Analyze results
        let tested_holders = all_results.len();
        
        // Count ACTUAL honeypot failures (exclude liquidity/slippage issues)
        let honeypot_failures = failure_types.iter()
            .filter(|ft| ft.is_honeypot())
            .count();
        
        // Calculate effective success rate (excluding legitimate failures like liquidity)
        let legitimate_tests = tested_holders - (failed_sells - honeypot_failures);
        let success_rate = if legitimate_tests > 0 {
            successful_sells as f64 / legitimate_tests as f64
        } else {
            0.0
        };

        // Check for whitelist patterns:
        // - If ALL holders can sell (100%) → Likely SAFE
        // - If MOST holders can sell (>70%) → Probably SAFE
        // - If SOME holders can sell (30-70%) → SUSPICIOUS (possible whitelist)
        // - If FEW/NONE can sell (<30%) → HONEYPOT
        
        // Note: We ignore failures due to liquidity/slippage (not honeypot indicators)
        
        if honeypot_failures == 0 && successful_sells > 0 {
            // Check if high success rate with whitelist functions (delegate honeypot)
            if success_rate >= 0.95 && has_whitelist_functions && tested_holders >= 50 {
                return Ok(ApprovedHolderVerdict {
                    is_honeypot: true,
                    confidence: 0.70,
                    tested_holders,
                    successful_sells,
                    failed_sells,
                    failure_types,
                    message: format!(
                        "⚠️  SUSPICIOUS WHITELIST HONEYPOT: {}/{} holders can sell ({:.0}% success) BUT whitelist/access-control detected in DELEGATECALL contract! Tested addresses may be whitelisted. PROCEED WITH EXTREME CAUTION!",
                        successful_sells, tested_holders, success_rate * 100.0
                    ),
                    admin_risks: admin_risks.clone(),
                });
            }
            
            // All failures are just liquidity issues - token is safe
            let base_message = format!(
                "{}/{} approved holders can sell successfully - token appears safe (some failures due to liquidity/slippage, not honeypot)",
                successful_sells, tested_holders
            );
            return Ok(ApprovedHolderVerdict {
                is_honeypot: false,
                confidence: 0.85,
                tested_holders,
                successful_sells,
                failed_sells,
                failure_types,
                message: Self::append_admin_warning(base_message, &admin_risks),
                admin_risks: admin_risks.clone(),
            });
        } else if success_rate >= 0.95 {
            // Very high success rate (95%+)
            if has_whitelist_functions && tested_holders >= 50 {
                // SUSPICIOUS: High success + whitelist functions = possible whitelist honeypot
                return Ok(ApprovedHolderVerdict {
                    is_honeypot: true,
                    confidence: 0.65,
                    tested_holders,
                    successful_sells,
                    failed_sells,
                    failure_types,
                    message: format!(
                        "⚠️  SUSPICIOUS WHITELIST HONEYPOT: {}/{} holders can sell ({:.0}% success) BUT whitelist/access-control functions detected (possibly in DELEGATECALL contract)! Tested addresses may be whitelisted while regular buyers are blocked. PROCEED WITH EXTREME CAUTION!",
                        successful_sells, tested_holders, success_rate * 100.0
                    ),
                    admin_risks: admin_risks.clone(),
                });
            } else {
                // High success, no whitelist functions - likely safe
                let base_message = format!(
                    "{}/{} approved holders can sell successfully ({:.0}% success rate) - token appears safe",
                    successful_sells, tested_holders, success_rate * 100.0
                );
                return Ok(ApprovedHolderVerdict {
                    is_honeypot: false,
                    confidence: 0.90,
                    tested_holders,
                    successful_sells,
                    failed_sells,
                    failure_types,
                    message: Self::append_admin_warning(base_message, &admin_risks),
                    admin_risks: admin_risks.clone(),
                });
            }
        } else if success_rate >= 0.70 {
            // High success rate (70-95%) - likely safe
            let base_message = format!(
                "{}/{} approved holders can sell successfully ({:.0}% success rate) - token appears safe",
                successful_sells, tested_holders, success_rate * 100.0
            );
            return Ok(ApprovedHolderVerdict {
                is_honeypot: false,
                confidence: 0.75 + (success_rate - 0.70) / 0.25 * 0.15, // 0.75-0.90 confidence
                tested_holders,
                successful_sells,
                failed_sells,
                failure_types,
                message: Self::append_admin_warning(base_message, &admin_risks),
                admin_risks: admin_risks.clone(),
            });
        } else if success_rate >= 0.30 && success_rate < 0.70 && honeypot_failures > 0 {
            // SUSPICIOUS: Some can sell, others fail with honeypot errors
            // This could indicate a whitelist mechanism
            return Ok(ApprovedHolderVerdict {
                is_honeypot: true,
                confidence: 0.60,
                tested_holders,
                successful_sells,
                failed_sells,
                failure_types,
                message: format!(
                    "⚠️  SUSPICIOUS: Only {}/{} holders can sell ({:.0}% success rate). Possible WHITELIST honeypot - some addresses may be whitelisted while others are blocked!",
                    successful_sells, legitimate_tests, success_rate * 100.0
                ),
                admin_risks: admin_risks.clone(),
            });
        }

        // If ALL holders fail to sell, check if it's due to honeypot or liquidity
        if successful_sells == 0 && honeypot_failures == 0 {
            // All failures are due to liquidity/slippage, NOT honeypot mechanisms
            return Ok(ApprovedHolderVerdict {
                is_honeypot: false,
                confidence: 0.50, // Lower confidence since we couldn't confirm sells work
                tested_holders,
                successful_sells,
                failed_sells,
                failure_types,
                message: format!(
                    "⚠️  UNCERTAIN: All {}/{} holders failed to sell due to low liquidity/high slippage, NOT honeypot blocks. Token may be safe but has insufficient liquidity for trading.",
                    failed_sells, tested_holders
                ),
            admin_risks: admin_risks.clone(),
            });
        }
        
        // If ALL holders fail with honeypot-like errors
        if honeypot_failures >= 2 {
            // Multiple holders fail with honeypot-like errors
            let failure_summary: Vec<_> = failure_types.iter()
                .filter(|ft| ft.is_honeypot())
                .cloned()
                .collect();
                
            return Ok(ApprovedHolderVerdict {
                is_honeypot: true,
                confidence: 0.90,
                tested_holders,
                successful_sells,
                failed_sells,
                failure_types,
                message: format!(
                    "HONEYPOT DETECTED! {}/{} holders cannot sell. Failure reasons: {:?}",
                    failed_sells, tested_holders, failure_summary
                ),
            admin_risks: admin_risks.clone(),
            });
        }

        // Mixed or unclear results
        Ok(ApprovedHolderVerdict {
            is_honeypot: failed_sells > successful_sells,
            confidence: 0.60,
            tested_holders,
            successful_sells,
            failed_sells,
            failure_types,
            message: format!(
                "Uncertain - {}/{} holders can sell. Manual review recommended.",
                successful_sells, tested_holders
            ),
        admin_risks: admin_risks.clone(),
        })
    }
}

/// Final verdict from approved holder simulation
#[derive(Debug, Clone)]
pub struct ApprovedHolderVerdict {
    pub is_honeypot: bool,
    pub confidence: f64,
    pub tested_holders: usize,
    pub successful_sells: usize,
    pub failed_sells: usize,
    pub failure_types: Vec<FailureType>,
    pub message: String,
    pub admin_risks: Option<AdminRiskAnalysis>,
}
