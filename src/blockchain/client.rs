use ethers::prelude::*;
use std::sync::Arc;
use crate::utils::{Result, DetectorError};

/// Blockchain RPC client
pub struct BlockchainClient {
    provider: Arc<Provider<Http>>,
    chain_id: u64,
}

impl BlockchainClient {
    /// Create a new client
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| DetectorError::RpcError(
                ProviderError::CustomError(format!("Invalid RPC URL: {}", e))
            ))?;
        
        let provider = Arc::new(provider);
        
        // Get chain ID
        let chain_id = provider.get_chainid().await?;
        
        tracing::info!("Connected to chain ID: {}", chain_id);
        
        Ok(Self {
            provider,
            chain_id: chain_id.as_u64(),
        })
    }
    
    /// Get bytecode at address
    pub async fn get_bytecode(&self, address: Address) -> Result<Vec<u8>> {
        tracing::debug!("Fetching bytecode for {:?}", address);
        
        let code = self.provider.get_code(address, None).await?;
        
        if code.is_empty() {
            return Err(DetectorError::ContractNotFound(format!("{:?}", address)));
        }
        
        Ok(code.to_vec())
    }
    
    /// Get storage at slot
    pub async fn get_storage(&self, address: Address, slot: H256) -> Result<H256> {
        let value = self.provider.get_storage_at(address, slot, None).await?;
        Ok(value)
    }
    
    /// Check if address is a contract
    pub async fn is_contract(&self, address: Address) -> Result<bool> {
        let code = self.provider.get_code(address, None).await?;
        Ok(!code.is_empty())
    }
    
    /// Get current block number
    pub async fn block_number(&self) -> Result<u64> {
        let block = self.provider.get_block_number().await?;
        Ok(block.as_u64())
    }
    
    /// Get chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    
    /// Get chain name
    pub fn chain_name(&self) -> &'static str {
        match self.chain_id {
            1 => "Ethereum Mainnet",
            369 => "PulseChain",
            943 => "PulseChain Testnet",
            _ => "Unknown Chain",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_pulsechain_connection() {
        let client = BlockchainClient::new("https://rpc.pulsechain.com")
            .await
            .expect("Failed to connect");
        
        assert_eq!(client.chain_id(), 369);
        assert_eq!(client.chain_name(), "PulseChain");
    }
    
    #[tokio::test]
    async fn test_fetch_bytecode() {
        let client = BlockchainClient::new("https://rpc.pulsechain.com")
            .await
            .expect("Failed to connect");
        
        // WPLS contract
        let wpls: Address = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27"
            .parse()
            .unwrap();
        
        let bytecode = client.get_bytecode(wpls).await.expect("Failed to get bytecode");
        
        assert!(!bytecode.is_empty());
        println!("WPLS bytecode length: {} bytes", bytecode.len());
    }
}
