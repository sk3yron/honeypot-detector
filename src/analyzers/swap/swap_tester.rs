//! Main swap simulation logic

use std::sync::Arc;
use ethers::types::{Address, U256};
use crate::blockchain::BlockchainClient;
use crate::contracts::{IPulseXFactory, IPulseXPair, addresses};
use crate::storage::LayoutDetector;
use crate::utils::{Result, DetectorError};
use super::{SwapTest, SwapResult, TestAmounts};

/// Swap simulator for PulseX
pub struct SwapSimulator {
    client: Arc<BlockchainClient>,
}

impl SwapSimulator {
    pub fn new(client: Arc<BlockchainClient>) -> Self {
        Self { client }
    }
    
    /// Test swaps for a token
    pub async fn test_swaps(&self, token: Address) -> Result<SwapTest> {
        tracing::info!("🔄 Testing PulseX swaps for {:?}", token);
        
        // Step 1: Find pair
        let pair_address = self.find_pair(token).await?;
        tracing::info!("Found pair: {:?}", pair_address);
        
        // Step 2: Get reserves
        let (reserve_token, reserve_wpls) = self.get_reserves(pair_address, token).await?;
        tracing::info!(
            "Reserves: {} tokens, {} WPLS",
            format_token_amount(reserve_token),
            format_token_amount(reserve_wpls)
        );
        
        // Step 3: Calculate test amounts
        let test_amounts = TestAmounts::from_liquidity(reserve_wpls);
        
        // Step 4: Detect storage layout
        let detector = LayoutDetector::new(self.client.clone());
        let layout = detector.detect(token).await?;
        tracing::info!("Storage layout: {}", layout.layout);
        
        // Step 5: Run buy tests
        tracing::info!("Testing BUY transactions...");
        let buy_micro = self.test_buy(token, test_amounts.micro, &layout).await.ok();
        let buy_normal = self.test_buy(token, test_amounts.normal, &layout).await.ok();
        let buy_large = self.test_buy(token, test_amounts.large, &layout).await.ok();
        
        // Step 6: Run sell tests  
        tracing::info!("Testing SELL transactions...");
        let sell_micro = self.test_sell(token, test_amounts.micro, &layout).await.ok();
        let sell_normal = self.test_sell(token, test_amounts.normal, &layout).await.ok();
        let sell_large = self.test_sell(token, test_amounts.large, &layout).await.ok();
        
        // Step 7: Calculate metrics
        let avg_buy_tax = calculate_avg_tax(&[&buy_micro, &buy_normal, &buy_large]);
        let avg_sell_tax = calculate_avg_tax(&[&sell_micro, &sell_normal, &sell_large]);
        
        // Step 8: Detect patterns
        let has_overflow_trap = detect_overflow(&buy_normal, &buy_large);
        let has_amount_limits = detect_amount_limits(&buy_micro, &buy_normal, &buy_large)
            || detect_amount_limits(&sell_micro, &sell_normal, &sell_large);
        
        // NEW: Detect if ALL sells fail (major honeypot indicator!)
        let all_sells_fail = [&sell_micro, &sell_normal, &sell_large]
            .iter()
            .filter_map(|r| r.as_ref())
            .all(|r| !r.success);
        
        // If any sells fail, mark as amount limits (catches honeypots)
        let has_amount_limits = has_amount_limits || all_sells_fail;
        
        Ok(SwapTest {
            buy_micro,
            buy_normal,
            buy_large,
            sell_micro,
            sell_normal,
            sell_large,
            avg_buy_tax,
            avg_sell_tax,
            has_overflow_trap,
            has_amount_limits,
        })
    }
    
    /// Find PulseX pair for token
    async fn find_pair(&self, token: Address) -> Result<Address> {
        let factory = IPulseXFactory::new(
            addresses::pulsex_factory(),
            self.client.provider.clone(),
        );
        
        let pair = factory.get_pair(token, addresses::wpls()).await
            .map_err(|e| crate::utils::DetectorError::ContractCallError(
                format!("Failed to get pair: {}", e)
            ))?;
        
        // Check if pair exists
        if pair == Address::zero() {
            return Err(crate::utils::DetectorError::AnalysisError(
                "No PulseX pair found for token".to_string()
            ));
        }
        
        Ok(pair)
    }
    
    /// Get reserves from pair
    async fn get_reserves(
        &self,
        pair: Address,
        token: Address,
    ) -> Result<(U256, U256)> {
        let pair_contract = IPulseXPair::new(pair, self.client.provider.clone());
        
        let (reserve0, reserve1, _timestamp) = pair_contract.get_reserves().await
            .map_err(|e| crate::utils::DetectorError::ContractCallError(
                format!("Failed to get reserves: {}", e)
            ))?;
        
        // Determine which reserve is token vs WPLS
        let token0 = pair_contract.token_0().await
            .map_err(|e| crate::utils::DetectorError::ContractCallError(
                format!("Failed to get token0: {}", e)
            ))?;
        
        let (reserve_token, reserve_wpls) = if token0 == token {
            (U256::from(reserve0), U256::from(reserve1))
        } else {
            (U256::from(reserve1), U256::from(reserve0))
        };
        
        Ok((reserve_token, reserve_wpls))
    }
    
    /// Test buy transaction using AMM math
    /// Simulates buying tokens with PLS using constant product formula
    async fn test_buy(
        &self,
        token: Address,
        amount_pls: U256,
        _layout: &crate::storage::LayoutInfo,
    ) -> Result<SwapResult> {
        tracing::debug!("Testing BUY with {} PLS", format_token_amount(amount_pls));
        
        // Get pair and reserves
        let pair = self.find_pair(token).await?;
        let (reserve_token, reserve_wpls) = self.get_reserves(pair, token).await?;
        
        // Check for U112 overflow risk
        let max_u112 = U256::from(2).pow(U256::from(112)) - 1;
        if reserve_token > max_u112 || reserve_wpls > max_u112 {
            return Ok(SwapResult {
                success: false,
                amount_in: amount_pls,
                amount_out: U256::zero(),
                gas_used: 0,
                revert_reason: Some("U112 overflow in reserves".to_string()),
                tax_percent: 0.0,
            });
        }
        
        // Calculate expected output using constant product formula
        // amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
        // The 997/1000 represents the 0.3% fee
        let amount_in_with_fee = amount_pls * U256::from(997);
        let numerator = amount_in_with_fee * reserve_token;
        let denominator = (reserve_wpls * U256::from(1000)) + amount_in_with_fee;
        
        if denominator.is_zero() {
            return Ok(SwapResult {
                success: false,
                amount_in: amount_pls,
                amount_out: U256::zero(),
                gas_used: 0,
                revert_reason: Some("Invalid reserves".to_string()),
                tax_percent: 0.0,
            });
        }
        
        let expected_out = numerator / denominator;
        
        // Calculate slippage/tax
        // In a perfect world with no tax: out = (in * reserveToken) / reservePLS
        let ideal_out = (amount_pls * reserve_token) / reserve_wpls;
        let tax_percent = if ideal_out > U256::zero() {
            let diff = if ideal_out > expected_out {
                ideal_out - expected_out
            } else {
                U256::zero()
            };
            (diff.as_u128() as f64 / ideal_out.as_u128() as f64) * 100.0
        } else {
            0.0
        };
        
        // Simulate success (AMM math, not full REVM execution)
        Ok(SwapResult {
            success: true,
            amount_in: amount_pls,
            amount_out: expected_out,
            gas_used: 200_000,
            revert_reason: None,
            tax_percent,
        })
    }
    
    /// Test sell transaction using eth_estimateGas
    /// This is simpler - estimateGas will fail if the transaction would revert!
    /// No need for actual balance or complex state setup
    async fn test_sell(
        &self,
        token: Address,
        amount_tokens: U256,
        _layout: &crate::storage::LayoutInfo,
    ) -> Result<SwapResult> {
        tracing::debug!("Testing SELL with {} tokens via estimateGas", format_token_amount(amount_tokens));
        
        use ethers::types::transaction::eip2718::TypedTransaction;
        use ethers::types::TransactionRequest;
        use ethers::providers::Middleware;
        
        // Get the pair address
        let pair = self.find_pair(token).await?;
        
        // Build calldata for: transfer(pair, amount_tokens)
        // This simulates selling tokens
        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256) selector
        
        // Encode pair address (32 bytes, left-padded)
        let mut pair_bytes = [0u8; 32];
        pair_bytes[12..32].copy_from_slice(pair.as_bytes());
        calldata.extend_from_slice(&pair_bytes);
        
        // Encode amount (32 bytes)
        let mut amount_bytes = [0u8; 32];
        amount_tokens.to_big_endian(&mut amount_bytes);
        calldata.extend_from_slice(&amount_bytes);
        
        // Use a test address that's unlikely to have balance issues
        // estimateGas is more lenient about balance checks
        let test_user: Address = "0x0000000000000000000000000000000000000999".parse().unwrap();
        
        let tx: TypedTransaction = TransactionRequest {
            from: Some(test_user),
            to: Some(token.into()),
            data: Some(calldata.into()),
            ..Default::default()
        }.into();
        
        // Use estimateGas instead of call
        // This will fail if the transaction would revert for ANY reason
        tracing::debug!("Calling eth_estimateGas for token.transfer(pair, {})...", amount_tokens);
        
        match self.client.provider.estimate_gas(&tx, None).await {
            Ok(gas_estimate) => {
                // Success! estimateGas returned without error
                tracing::info!("✅ SELL succeeded - gas estimate: {}", gas_estimate);
                
                Ok(SwapResult {
                    success: true,
                    amount_in: amount_tokens,
                    amount_out: amount_tokens, // Simplified for now
                    gas_used: gas_estimate.as_u64(),
                    revert_reason: None,
                    tax_percent: 0.0,
                })
            }
            Err(e) => {
                // Transaction reverted! This is a honeypot
                let revert_reason = parse_provider_error(&e);
                
                tracing::warn!("❌ SELL FAILED - transfer reverted: {}", revert_reason);
                tracing::warn!("   This indicates a HONEYPOT - token blocks sells!");
                
                Ok(SwapResult {
                    success: false,
                    amount_in: amount_tokens,
                    amount_out: U256::zero(),
                    gas_used: 0,
                    revert_reason: Some(revert_reason),
                    tax_percent: 0.0,
                })
            }
        }
    }
}

// Helper functions

fn parse_provider_error(error: &ethers::providers::ProviderError) -> String {
    let error_str = format!("{:?}", error);
    
    // Try to extract revert reason from error message
    // Common patterns:
    // - "execution reverted: REASON"
    // - "execution reverted" (no reason)
    // - Error data: 0x... (custom error)
    
    if let Some(start) = error_str.find("execution reverted") {
        // Extract everything after "execution reverted"
        let after = &error_str[start..];
        
        if let Some(colon_pos) = after.find(':') {
            // Has a reason after the colon
            let reason = &after[colon_pos+1..];
            // Clean up the reason (remove quotes, brackets, etc)
            reason.trim()
                .trim_matches('"')
                .trim_matches('\'')
                .chars()
                .take(200)
                .collect()
        } else {
            "execution reverted (no reason)".to_string()
        }
    } else if error_str.contains("0x") {
        // Try to extract hex error data
        if let Some(hex_start) = error_str.find("0x") {
            let hex_part = &error_str[hex_start..];
            let hex_end = hex_part.find(|c: char| !c.is_ascii_hexdigit() && c != 'x')
                .unwrap_or(hex_part.len().min(66)); // Take up to 32 bytes
            
            format!("Reverted with data: {}", &hex_part[..hex_end])
        } else {
            "Transaction reverted (unknown reason)".to_string()
        }
    } else {
        // Generic error
        error_str.chars().take(200).collect()
    }
}

fn format_token_amount(amount: U256) -> String {
    let decimals = U256::from(10).pow(U256::from(18));
    let whole = amount / decimals;
    format!("{}", whole)
}

fn calculate_avg_tax(results: &[&Option<SwapResult>]) -> f64 {
    let valid_results: Vec<f64> = results
        .iter()
        .filter_map(|r| r.as_ref())
        .filter(|r| r.success)
        .map(|r| r.tax_percent)
        .collect();
    
    if valid_results.is_empty() {
        return 0.0;
    }
    
    valid_results.iter().sum::<f64>() / valid_results.len() as f64
}

fn detect_overflow(normal: &Option<SwapResult>, large: &Option<SwapResult>) -> bool {
    match (normal, large) {
        (Some(n), Some(l)) => {
            // If normal succeeds but large fails, might be U112 overflow
            n.success && !l.success
        }
        _ => false,
    }
}

fn detect_amount_limits(
    micro: &Option<SwapResult>,
    normal: &Option<SwapResult>,
    large: &Option<SwapResult>,
) -> bool {
    // Different results for different amounts suggests amount-dependent logic
    let results: Vec<bool> = [micro, normal, large]
        .iter()
        .filter_map(|r| r.as_ref())
        .map(|r| r.success)
        .collect();
    
    if results.len() < 2 {
        return false;
    }
    
    // If not all the same, there's amount-dependent behavior
    !results.iter().all(|&r| r == results[0])
}
