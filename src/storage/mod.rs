//! Storage layout detection for ERC20 tokens
//! 
//! Different ERC20 implementations use different storage layouts.
//! This module detects the layout to enable accurate storage manipulation in REVM.

mod layout;
mod slot_calculator;

pub use layout::{StorageLayout, LayoutInfo};
pub use slot_calculator::{calculate_mapping_slot, calculate_nested_mapping_slot, keccak256_concat};

use std::sync::Arc;
use ethers::types::{Address, U256, H256};
use crate::blockchain::BlockchainClient;
use crate::contracts::IERC20;
use crate::utils::{Result, DetectorError};

/// Storage layout detector
pub struct LayoutDetector {
    client: Arc<BlockchainClient>,
}

impl LayoutDetector {
    pub fn new(client: Arc<BlockchainClient>) -> Self {
        Self { client }
    }
    
    /// Detect storage layout for a token
    /// 
    /// Strategy:
    /// 1. Find a holder with non-zero balance
    /// 2. Query balance via balanceOf()
    /// 3. Try slots 0-10, calculate mapping slot
    /// 4. Read storage and compare with balanceOf result
    /// 5. Return matching layout
    pub async fn detect(&self, token: Address) -> Result<LayoutInfo> {
        tracing::info!("🔍 Detecting storage layout for {:?}", token);
        
        // Try to find a holder with balance
        let holder = self.find_holder(token).await?;
        
        tracing::debug!("Found holder {:?} for testing", holder);
        
        // Get expected balance via RPC call
        let token_contract = IERC20::new(token, self.client.provider.clone());
        let expected_balance = token_contract.balance_of(holder).await
            .map_err(|e| DetectorError::ContractCallError(format!("balanceOf failed: {}", e)))?;
        
        if expected_balance.is_zero() {
            tracing::warn!("Holder has zero balance, trying auto-detect with different address");
        }
        
        tracing::debug!("Expected balance: {}", expected_balance);
        
        // Try standard layouts first
        for slot in 0..=10u8 {
            let storage_slot = calculate_mapping_slot(holder, slot);
            
            // Convert U256 to H256 for storage query
            let mut slot_bytes = [0u8; 32];
            storage_slot.to_big_endian(&mut slot_bytes);
            let h256_slot = H256::from(slot_bytes);
            
            match self.client.get_storage(token, h256_slot).await {
                Ok(value) => {
                    let stored_balance = U256::from_big_endian(value.as_bytes());
                    
                    if stored_balance == expected_balance && !stored_balance.is_zero() {
                        tracing::info!("✅ Found matching storage at slot {}", slot);
                        
                        let layout = match slot {
                            0 => StorageLayout::OpenZeppelin,
                            3 => StorageLayout::Solmate,
                            _ => StorageLayout::Custom(slot),
                        };
                        
                        return Ok(LayoutInfo {
                            layout,
                            balances_slot: slot,
                            verified: true,
                        });
                    }
                }
                Err(e) => {
                    tracing::debug!("Error reading slot {}: {}", slot, e);
                }
            }
        }
        
        // Could not detect
        tracing::warn!("❌ Could not detect storage layout");
        Ok(LayoutInfo {
            layout: StorageLayout::Unknown,
            balances_slot: 0,
            verified: false,
        })
    }
    
    /// Find a holder address (try token contract itself, or use a test address)
    async fn find_holder(&self, token: Address) -> Result<Address> {
        // Try the token contract itself as holder
        let token_contract = IERC20::new(token, self.client.provider.clone());
        
        // Try a few common addresses
        let test_addresses = vec![
            token, // Token contract itself
            "0x0000000000000000000000000000000000000001".parse().unwrap(),
            "0x0000000000000000000000000000000000000002".parse().unwrap(),
        ];
        
        for addr in test_addresses {
            if let Ok(balance) = token_contract.balance_of(addr).await {
                if !balance.is_zero() {
                    return Ok(addr);
                }
            }
        }
        
        // Default to token address
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_slot_calculation() {
        let addr: Address = "0x0000000000000000000000000000000000000001".parse().unwrap();
        let slot = calculate_mapping_slot(addr, 0);
        
        // Result should be a valid U256
        assert!(slot > U256::zero());
    }
}
