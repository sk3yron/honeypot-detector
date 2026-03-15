use honeypot_detector::analyzers::ApprovedHolderSimulator;
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();

    let tokens = vec![
        ("0x463413c579D29c26D59a65312657DFCe30D545A1", "Token with mint, renounced"),
        ("0xb1f52D529390Ec28483Fe7689A4eA26Fce2956f4", "Honeypot token"),
    ];

    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    let simulator = ApprovedHolderSimulator::new(client);

    for (addr, desc) in tokens {
        println!("\n============================================================");
        println!("Testing: {}", desc);
        println!("Address: {}", addr);
        println!("============================================================");
        
        let token: ethers::types::Address = addr.parse()?;
        
        match simulator.detect_admin_functions(token).await {
            Ok(admin) => {
                println!("\n✅ Admin Analysis:");
                println!("   Mint: {}", admin.has_mint);
                println!("   Burn: {}", admin.has_burn);
                println!("   Pause: {}", admin.has_pause);
                println!("   Blacklist: {}", admin.has_blacklist);
                println!("   Owner: {:?}", admin.owner_address);
                println!("   Renounced: {}", admin.is_renounced);
                println!("   Risk: {:?}", admin.risk_level);
                println!("   Summary: {}", admin.summary);
            }
            Err(e) => println!("❌ Error: {}", e),
        }
    }

    Ok(())
}
