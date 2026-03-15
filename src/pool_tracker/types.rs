use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolInfo {
    pub pair: Address,
    pub token0: Address,
    pub token1: Address,
    pub reserve0: U256,
    pub reserve1: U256,
    pub last_updated_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolCache {
    pub pools: HashMap<Address, PoolInfo>,
    pub last_synced_block: u64,
    pub last_updated: String, // ISO timestamp
}

impl PoolCache {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            last_synced_block: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }
    
    pub fn update_pool(
        &mut self,
        pair: Address,
        token0: Address,
        token1: Address,
        reserve0: U256,
        reserve1: U256,
        block: u64,
    ) {
        if let Some(pool) = self.pools.get_mut(&pair) {
            pool.reserve0 = reserve0;
            pool.reserve1 = reserve1;
            pool.last_updated_block = block;
        } else {
            // New pool discovered
            tracing::info!("📍 New pool discovered: {:?}", pair);
            self.pools.insert(pair, PoolInfo {
                pair,
                token0,
                token1,
                reserve0,
                reserve1,
                last_updated_block: block,
            });
        }
        
        self.last_synced_block = block;
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }
    
    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }
}
