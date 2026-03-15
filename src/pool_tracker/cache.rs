use super::types::PoolCache;
use std::path::Path;
use anyhow::Result;
use ethers::types::Address;

impl PoolCache {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let cache: PoolCache = serde_json::from_str(&contents)?;
        tracing::info!("✅ Loaded {} pools from cache", cache.pools.len());
        Ok(cache)
    }
    
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    pub fn find_pool_for_token(&self, token: Address, paired_with: Address) -> Option<&super::types::PoolInfo> {
        self.pools.values().find(|pool| {
            (pool.token0 == token && pool.token1 == paired_with) ||
            (pool.token1 == token && pool.token0 == paired_with)
        })
    }
}
