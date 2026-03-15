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

    println!("\n🔍 Admin/Owner Privilege Detection Test");
    println!("========================================\n");

    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    let simulator = ApprovedHolderSimulator::new(client);

    for (addr, desc) in tokens {
        println!("============================================================");
        println!("Testing: {}", desc);
        println!("Address: {}", addr);
        println!("============================================================");
        
        let token: ethers::types::Address = addr.parse()?;
        
        match simulator.detect_admin_functions(token).await {
            Ok(admin) => {
                println!("\n✅ Admin Analysis:");
                println!("   • Mint function: {}", if admin.has_mint { "YES" } else { "NO" });
                println!("   • Burn function: {}", if admin.has_burn { "YES" } else { "NO" });
                println!("   • Pause function: {}", if admin.has_pause { "YES" } else { "NO" });
                println!("   • Blacklist function: {}", if admin.has_blacklist { "YES" } else { "NO" });
                
                if let Some(owner) = admin.owner_address {
                    println!("\n   👤 Owner: {}", owner);
                    println!("   📋 Status: {}", if admin.is_renounced { 
                        "RENOUNCED ✅" 
                    } else { 
                        "ACTIVE ⚠️" 
                    });
                }
                
                println!("\n   📊 Risk Level: {:?}", admin.risk_level);
                println!("   💬 {}\n", admin.summary);
            }
            Err(e) => println!("❌ Error: {}\n", e),
        }
    }

    Ok(())
}
