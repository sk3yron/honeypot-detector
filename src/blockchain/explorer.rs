use std::sync::Arc;
use ethers::types::Address;
use serde::{Deserialize, Serialize};
use crate::utils::{Result, DetectorError};

/// Block explorer for fetching verified source code
pub struct BlockExplorer {
    chain_id: u64,
    cache: Arc<sled::Db>,
    api_key: Option<String>,
}

/// Verified source code information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCode {
    pub source: String,
    pub contract_name: String,
    pub compiler_version: String,
    pub optimization: bool,
    pub runs: u32,
}

/// API response from block explorer
#[derive(Debug, Deserialize)]
struct ExplorerResponse {
    status: String,
    result: Vec<ExplorerResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExplorerResult {
    source_code: String,
    contract_name: String,
    compiler_version: String,
    optimization_used: String,
    runs: String,
}

impl BlockExplorer {
    /// Create a new block explorer instance
    pub fn new(chain_id: u64, cache: Arc<sled::Db>) -> Self {
        let api_key = match chain_id {
            56 => std::env::var("BSCSCAN_API_KEY").ok(),
            1 => std::env::var("ETHERSCAN_API_KEY").ok(),
            369 => std::env::var("PULSESCAN_API_KEY").ok(),
            _ => None,
        };
        
        Self {
            chain_id,
            cache,
            api_key,
        }
    }
    
    /// Get API endpoint for the chain
    fn get_api_endpoint(&self) -> &'static str {
        match self.chain_id {
            56 => "https://api.bscscan.com/api",
            1 => "https://api.etherscan.io/api",
            369 => "https://api.scan.pulsechain.com/api",
            _ => "https://api.scan.pulsechain.com/api", // Default to PulseChain
        }
    }
    
    /// Get cache key for an address
    fn cache_key(&self, address: Address) -> String {
        format!("source_code:{}:{:?}", self.chain_id, address)
    }
    
    /// Get verified source code for a contract
    pub async fn get_source_code(&self, address: Address) -> Result<Option<SourceCode>> {
        let cache_key = self.cache_key(address);
        
        // Check cache first
        if let Ok(Some(cached)) = self.cache.get(cache_key.as_bytes()) {
            if let Ok(source_code) = bincode::deserialize::<Option<SourceCode>>(&cached) {
                tracing::debug!("Source code cache hit for {:?}", address);
                return Ok(source_code);
            }
        }
        
        tracing::info!("Fetching source code for {:?} from block explorer", address);
        
        // Fetch from API
        let result = self.fetch_source_code(address).await?;
        
        // Cache the result (even if None, to avoid repeated API calls)
        let cached_value = bincode::serialize(&result)
            .map_err(|e| DetectorError::CacheError(format!("Serialization failed: {}", e)))?;
        self.cache.insert(cache_key.as_bytes(), cached_value)
            .map_err(|e| DetectorError::CacheError(format!("Cache insert failed: {}", e)))?;
        
        Ok(result)
    }
    
    /// Fetch source code from API
    async fn fetch_source_code(&self, address: Address) -> Result<Option<SourceCode>> {
        let endpoint = self.get_api_endpoint();
        let address_str = format!("{:?}", address);
        
        let client = reqwest::Client::new();
        let mut request = client.get(endpoint)
            .query(&[
                ("module", "contract"),
                ("action", "getsourcecode"),
                ("address", &address_str),
            ]);
        
        // Add API key if available
        if let Some(ref key) = self.api_key {
            request = request.query(&[("apikey", key)]);
        }
        
        let response = request
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Explorer API request failed: {}", e)))?;
        
        let explorer_response: ExplorerResponse = response
            .json()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Failed to parse explorer response: {}", e)))?;
        
        if explorer_response.status != "1" {
            return Ok(None);
        }
        
        if let Some(result) = explorer_response.result.first() {
            // Check if source code is actually available
            if result.source_code.is_empty() || result.source_code == "null" {
                return Ok(None);
            }
            
            let optimization = result.optimization_used == "1";
            let runs = result.runs.parse::<u32>().unwrap_or(200);
            
            Ok(Some(SourceCode {
                source: result.source_code.clone(),
                contract_name: result.contract_name.clone(),
                compiler_version: result.compiler_version.clone(),
                optimization,
                runs,
            }))
        } else {
            Ok(None)
        }
    }
    
    /// Clear cache for a specific address
    pub fn clear_cache(&self, address: Address) -> Result<()> {
        let cache_key = self.cache_key(address);
        self.cache.remove(cache_key.as_bytes())
            .map_err(|e| DetectorError::CacheError(format!("Cache removal failed: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_api_endpoint() {
        let cache = Arc::new(sled::Config::new().temporary(true).open().unwrap());
        
        let bsc_explorer = BlockExplorer::new(56, cache.clone());
        assert_eq!(bsc_explorer.get_api_endpoint(), "https://api.bscscan.com/api");
        
        let eth_explorer = BlockExplorer::new(1, cache.clone());
        assert_eq!(eth_explorer.get_api_endpoint(), "https://api.etherscan.io/api");
        
        let pulse_explorer = BlockExplorer::new(369, cache.clone());
        assert_eq!(pulse_explorer.get_api_endpoint(), "https://api.scan.pulsechain.com/api");
    }
}
