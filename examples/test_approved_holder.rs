use honeypot_detector::analyzers::ApprovedHolderSimulator;
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();

    println!("🔍 PulseChain Honeypot Detector - Approved Holder Simulation");
    println!("=============================================================\n");

    // Connect to PulseChain
    println!("📡 Connecting to PulseChain RPC...");
    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    println!("✅ Connected to {}\n", client.chain_name());
    
    // Test with a legit token
    let token: ethers::types::Address = "0x2A06a971fE6ffa002fd242d437E3db2b5cC5B433".parse()?;
    
    println!("🎯 Testing Token: {:?}", token);
    println!("Expected: Legit token\n");
    
    // Create simulator
    let simulator = ApprovedHolderSimulator::new(client);
    
    println!("🚀 Running approved holder simulation test...\n");
    
    match simulator.run_complete_test(token).await {
        Ok(verdict) => {
            println!("\n📊 SIMULATION RESULTS:");
            println!("=====================");
            println!("Tested holders: {}", verdict.tested_holders);
            println!("Successful sells: {}", verdict.successful_sells);
            println!("Failed sells: {}", verdict.failed_sells);
            println!();
            
            if !verdict.failure_types.is_empty() {
                println!("Failure types:");
                for (i, failure_type) in verdict.failure_types.iter().enumerate() {
                    println!("  {}. {:?}", i + 1, failure_type);
                }
                println!();
            }
            
            println!("📈 VERDICT:");
            println!("===========");
            if verdict.is_honeypot {
                println!("🔴 HONEYPOT DETECTED!");
            } else {
                println!("🟢 Appears SAFE");
            }
            println!("Confidence: {:.0}%", verdict.confidence * 100.0);
            println!("Message: {}", verdict.message);
        }
        Err(e) => {
            println!("❌ Error running simulation: {}", e);
            println!("This could mean:");
            println!("  - RPC connection issues");
            println!("  - Token doesn't exist");
            println!("  - No trading history available");
            return Err(e.into());
        }
    }
    
    Ok(())
}
