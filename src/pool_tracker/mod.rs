pub mod types;
pub mod event_fetcher;
pub mod cache;

use ethers::prelude::*;
use anyhow::Result;
use std::time::Duration;
use tokio::time;

pub use types::*;
pub use event_fetcher::*;

pub struct PoolTracker {
    provider: Provider<Http>,
    cache: PoolCache,
    cache_path: String,
    poll_interval: Duration,
    factory: Address,
}

impl PoolTracker {
    pub fn new(rpc_url: &str, cache_path: String) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        let cache = if std::path::Path::new(&cache_path).exists() {
            PoolCache::load_from_file(&cache_path)?
        } else {
            tracing::info!("📝 Creating new pool cache");
            PoolCache::new()
        };
        
        // PulseX V2 Factory
        let factory: Address = "0x29eA7545DEf87022BAdc76323F373EA1e707C523".parse()?;
        
        Ok(Self {
            provider,
            cache,
            cache_path,
            poll_interval: Duration::from_secs(3),
            factory,
        })
    }
    
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("🚀 Pool Tracker started");
        tracing::info!("📊 Last synced block: {}", self.cache.last_synced_block);
        tracing::info!("💾 Cache file: {}", self.cache_path);
        
        loop {
            if let Err(e) = self.sync_pools().await {
                tracing::error!("❌ Sync error: {}", e);
                // Wait a bit longer on error
                time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            
            time::sleep(self.poll_interval).await;
        }
    }
    
    async fn sync_pools(&mut self) -> Result<()> {
        let current_block = self.provider.get_block_number().await?.as_u64();
        
        if current_block <= self.cache.last_synced_block {
            return Ok(());
        }
        
        let from_block = if self.cache.last_synced_block == 0 {
            // First run - start from recent block (last 1000 blocks to not overload RPC)
            tracing::info!("🆕 First run - scanning last 1000 blocks");
            current_block.saturating_sub(1000)
        } else {
            self.cache.last_synced_block + 1
        };
        
        let blocks_to_scan = current_block - from_block + 1;
        
        tracing::info!(
            "🔍 Syncing blocks {} to {} ({} blocks)",
            from_block,
            current_block,
            blocks_to_scan
        );
        
        // Fetch Sync events
        let logs = fetch_sync_events(&self.provider, from_block, current_block).await?;
        
        tracing::info!("📦 Found {} Sync events", logs.len());
        
        // Process events
        for log in logs {
            let pair = log.address;
            let (reserve0, reserve1) = decode_sync_event(&log.data);
            let block = log.block_number.unwrap_or_default().as_u64();
            
            // Get token addresses from pair if new pool
            if !self.cache.pools.contains_key(&pair) {
                match self.get_pair_tokens(pair).await {
                    Ok((token0, token1)) => {
                        self.cache.update_pool(pair, token0, token1, reserve0, reserve1, block);
                    }
                    Err(e) => {
                        tracing::warn!("⚠️  Failed to get tokens for pair {:?}: {}", pair, e);
                        continue;
                    }
                }
            } else {
                // Existing pool - just update reserves
                if let Some(pool) = self.cache.pools.get(&pair) {
                    let token0 = pool.token0;
                    let token1 = pool.token1;
                    self.cache.update_pool(pair, token0, token1, reserve0, reserve1, block);
                }
            }
        }
        
        // Save to disk
        self.cache.save_to_file(&self.cache_path)?;
        tracing::info!("💾 Saved {} pools to {}", self.cache.pool_count(), self.cache_path);
        
        Ok(())
    }
    
    async fn get_pair_tokens(&self, pair: Address) -> Result<(Address, Address)> {
        // Call token0() and token1() on the pair contract
        use ethers::abi::AbiEncode;
        
        // token0() selector: 0x0dfe1681
        let token0_call = hex::decode("0dfe1681")?;
        let tx0 = TransactionRequest::new()
            .to(pair)
            .data(token0_call);
        let token0_bytes = self.provider.call(&tx0.into(), None).await?;
        let token0 = Address::from_slice(&token0_bytes[12..32]);
        
        // token1() selector: 0xd21220a7
        let token1_call = hex::decode("d21220a7")?;
        let tx1 = TransactionRequest::new()
            .to(pair)
            .data(token1_call);
        let token1_bytes = self.provider.call(&tx1.into(), None).await?;
        let token1 = Address::from_slice(&token1_bytes[12..32]);
        
        Ok((token0, token1))
    }
}
