use honeypot_detector::pool_tracker::PoolTracker;
use tracing_subscriber;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();
    
    println!("╔══════════════════════════════════════════════╗");
    println!("║     PulseChain Pool Tracker v1.0            ║");
    println!("║     Real-time DEX Pool Monitoring           ║");
    println!("╚══════════════════════════════════════════════╝\n");
    
    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://rpc.pulsechain.com".to_string());
    
    let cache_path = "data/pools.json".to_string();
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all("data")?;
    
    println!("🌐 RPC: {}", rpc_url);
    println!("💾 Cache: {}\n", cache_path);
    
    let mut tracker = PoolTracker::new(&rpc_url, cache_path)?;
    
    tracker.run().await
}
