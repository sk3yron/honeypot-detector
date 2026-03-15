use ethers::prelude::*;
use std::str::FromStr;

const SYNC_EVENT_SIGNATURE: &str = 
    "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1";

pub async fn fetch_sync_events(
    provider: &Provider<Http>,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Log>, ProviderError> {
    let sync_topic = H256::from_str(SYNC_EVENT_SIGNATURE)
        .map_err(|e| ProviderError::CustomError(format!("Invalid topic: {}", e)))?;
    
    let filter = Filter::new()
        .topic0(sync_topic)
        .from_block(from_block)
        .to_block(to_block);
    
    tracing::debug!("Fetching Sync events from block {} to {}", from_block, to_block);
    
    provider.get_logs(&filter).await
}

pub fn decode_sync_event(data: &Bytes) -> (U256, U256) {
    // Sync event data: reserve0 (32 bytes) + reserve1 (32 bytes)
    let reserve0 = U256::from_big_endian(&data[0..32]);
    let reserve1 = U256::from_big_endian(&data[32..64]);
    
    (reserve0, reserve1)
}
