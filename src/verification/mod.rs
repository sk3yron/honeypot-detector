//! Factory and deployer verification (Tier 0)
//! 
//! Provides instant verdicts for tokens created by known factories or deployers

mod factories;
mod deployers;

pub use factories::{TRUSTED_FACTORIES, is_trusted_factory};
pub use deployers::{KNOWN_SCAMMERS, is_known_scammer};

use std::sync::Arc;
use ethers::types::Address;
use crate::blockchain::BlockchainClient;
use crate::utils::Result;

/// Factory verification verdict
#[derive(Debug, Clone)]
pub enum FactoryVerdict {
    /// Token created by trusted factory
    TrustedFactory {
        factory: Address,
        confidence: f64,
    },
    
    /// Token created by known scammer
    KnownScammer {
        deployer: Address,
        confidence: f64,
    },
    
    /// Unknown factory/deployer
    Unknown,
}

/// Factory and deployer verifier
pub struct FactoryVerifier {
    client: Arc<BlockchainClient>,
}

impl FactoryVerifier {
    pub fn new(client: Arc<BlockchainClient>) -> Self {
        Self { client }
    }
    
    /// Verify token creator/factory
    /// 
    /// Returns instant verdict if deployer is in whitelist/blacklist
    pub async fn verify(&self, token: Address) -> Result<FactoryVerdict> {
        tracing::info!("🏭 Verifying factory/deployer for {:?}", token);
        
        // Get deployer address
        let deployer = self.get_deployer(token).await?;
        
        tracing::debug!("Token deployer: {:?}", deployer);
        
        // Check trusted factories
        if is_trusted_factory(deployer) {
            tracing::info!("✅ Trusted factory detected!");
            return Ok(FactoryVerdict::TrustedFactory {
                factory: deployer,
                confidence: 0.95,
            });
        }
        
        // Check known scammers
        if is_known_scammer(deployer) {
            tracing::warn!("🚨 Known scammer detected!");
            return Ok(FactoryVerdict::KnownScammer {
                deployer,
                confidence: 0.95,
            });
        }
        
        // Unknown
        Ok(FactoryVerdict::Unknown)
    }
    
    /// Get deployer address from token creation
    /// 
    /// Note: This is a simplified implementation that returns the token address itself
    /// In production, you'd want to query the creation transaction via eth_getCode or similar
    async fn get_deployer(&self, token: Address) -> Result<Address> {
        // TODO: Implement proper deployer detection via transaction history
        // For now, return the token address as placeholder
        // In Phase 2, we can enhance this by:
        // 1. Using eth_getTransactionByHash to find creation tx
        // 2. Checking if created via factory (CREATE2)
        // 3. Extracting actual deployer address
        
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[test]
    fn test_trusted_factory_detection() {
        let pump_tires = Address::from_str("0xcf6402cdEdfF50Fe334471D0fDD33014E40e828c").unwrap();
        assert!(is_trusted_factory(pump_tires));
    }
    
    #[test]
    fn test_unknown_address() {
        let random = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        assert!(!is_trusted_factory(random));
        assert!(!is_known_scammer(random));
    }
}
