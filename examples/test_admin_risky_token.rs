use honeypot_detector::analyzers::ApprovedHolderSimulator;
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();

    // Test various token scenarios
    let test_cases = vec![
        ("0x463413c579D29c26D59a65312657DFCe30D545A1", 
         "Token with mint + renounced owner (Low Risk)"),
        
        ("0xb1f52D529390Ec28483Fe7689A4eA26Fce2956f4", 
         "Honeypot token (should show admin analysis)"),
    ];

    println!("\n{}", "=".repeat(80));
    println!("🔒 Admin/Owner Risk Detection - Comprehensive Test");
    println!("{}\n", "=".repeat(80));

    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    let simulator = ApprovedHolderSimulator::new(client);

    for (i, (addr, desc)) in test_cases.iter().enumerate() {
        println!("Test Case {}: {}", i + 1, desc);
        println!("{}", "-".repeat(80));
        println!("Address: {}\n", addr);
        
        let token: ethers::types::Address = addr.parse()?;
        
        match simulator.detect_admin_functions(token).await {
            Ok(admin) => {
                println!("Admin Functions Detected:");
                
                let mut privileges = vec![];
                if admin.has_mint { privileges.push("mint()"); }
                if admin.has_burn { privileges.push("burn()"); }
                if admin.has_pause { privileges.push("pause()"); }
                if admin.has_blacklist { privileges.push("blacklist()"); }
                
                if privileges.is_empty() {
                    println!("  ✅ No dangerous admin functions found");
                } else {
                    println!("  ⚠️  Functions: {}", privileges.join(", "));
                }
                
                if let Some(owner) = admin.owner_address {
                    println!("\nOwner Status:");
                    println!("  Address: {}", owner);
                    if admin.is_renounced {
                        println!("  Status: ✅ RENOUNCED (Cannot execute admin functions)");
                    } else {
                        println!("  Status: ⚠️  ACTIVE (Can execute admin functions)");
                    }
                }
                
                println!("\nRisk Assessment:");
                println!("  Level: {:?}", admin.risk_level);
                println!("  Summary: {}", admin.summary);
                
                // Display recommendation
                use honeypot_detector::analyzers::swap::AdminRiskLevel;
                match admin.risk_level {
                    AdminRiskLevel::None => {
                        println!("\n  ✅ RECOMMENDATION: Safe from admin rug risks");
                    }
                    AdminRiskLevel::Low => {
                        println!("\n  ✅ RECOMMENDATION: Low risk - Owner renounced");
                    }
                    AdminRiskLevel::Medium => {
                        println!("\n  ⚠️  RECOMMENDATION: Medium risk - Monitor owner activity");
                    }
                    AdminRiskLevel::High | AdminRiskLevel::Critical => {
                        println!("\n  🔴 RECOMMENDATION: HIGH RISK - Owner can rug pull!");
                        println!("     DO NOT INVEST without thorough research!");
                    }
                }
            }
            Err(e) => {
                println!("❌ Error analyzing token: {}", e);
            }
        }
        
        println!("\n{}\n", "=".repeat(80));
    }

    Ok(())
}
