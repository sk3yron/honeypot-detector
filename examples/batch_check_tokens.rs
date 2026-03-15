use honeypot_detector::analyzers::swap::{ApprovedHolderSimulator, AdminRiskLevel};
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=warn")
        .init();

    // Tokens from user's list
    let tokens = vec![
        ("0x1D177CB9EfEEa49A8B97ab1C72785a3A37ABc9Ff", "FD"),
        ("0x812571A12330A74E2A3C1fF8953f6f3aac7a83e9", "DC"),
        ("0x51160F352ED148C89d48dfe6384Edd07aFA24E0E", "FM"),
        ("0xe37acc54711562510fafc45d8199ee329ebbcedd", "PARADE"),
        ("0xC7145e1290B1d1221Aba5Ae48d4aCE17c6BE088F", "Tellerz"),
        ("0x6a8ee78653c588530d31fa308f4b165f346bd9e0", "Token6"),
        ("0x1c27fd7ab4faa8141119484e00d2455851639c2b", "SSA"),
        ("0xdb4ebeafb23eca5275821ab0d87c7f6fa5514ea4", "SCOIETY"),
        ("0xD33358F1B3130e2E9715C5992028D9de384544E8", "CAMPAIGN"),
        ("0x7Ba907a5d308024E2A2010ea60318b834c1D8E9E", "OPIUM"),
        ("0xf5f1E1B45524cf6919e7Ce3EdDB83569eC452aea", "Token11"),
        ("0x921Bc9A18EaF7299Ae42c1cc416ef070b04EF81E", "TEHATER"),
        ("0xca803da0dF03c7E0897ff09bC53369654be0e3E7", "Token13"),
        ("0xaAE18Cd46C45d343BbA1eab46716B4D69d799734", "BAR"),
    ];

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║         BATCH TOKEN SECURITY ANALYSIS - {} TOKENS            ║", tokens.len());
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    let simulator = ApprovedHolderSimulator::new(client);

    let mut results = Vec::new();

    for (i, (addr, name)) in tokens.iter().enumerate() {
        println!("═══════════════════════════════════════════════════════════════");
        println!("Token {}/{}  -  {}", i + 1, tokens.len(), name);
        println!("Address: {}", addr);
        println!("═══════════════════════════════════════════════════════════════");
        
        let token: ethers::types::Address = match addr.parse() {
            Ok(t) => t,
            Err(e) => {
                println!("❌ Invalid address: {}\n", e);
                results.push((name.to_string(), AdminRiskLevel::Critical, "Invalid address".to_string(), true));
                continue;
            }
        };
        
        // Check admin functions
        print!("🔍 Analyzing admin privileges... ");
        match simulator.detect_admin_functions(token).await {
            Ok(admin) => {
                println!("Done!\n");
                
                // Display admin analysis
                let mut issues = Vec::new();
                
                if admin.has_mint { issues.push("MINT"); }
                if admin.has_burn { issues.push("BURN"); }
                if admin.has_pause { issues.push("PAUSE"); }
                if admin.has_blacklist { issues.push("BLACKLIST"); }
                
                if !issues.is_empty() {
                    println!("⚠️  Admin Functions: {}", issues.join(", "));
                } else {
                    println!("✅ No dangerous admin functions detected");
                }
                
                if let Some(owner) = admin.owner_address {
                    println!("👤 Owner: {}", owner);
                    if admin.is_renounced {
                        println!("   ✅ Status: RENOUNCED");
                    } else {
                        println!("   ⚠️  Status: ACTIVE (can execute admin functions)");
                    }
                } else {
                    println!("👤 Owner: Not detected or no owner() function");
                }
                
                // Risk assessment
                let risk_emoji = match admin.risk_level {
                    AdminRiskLevel::None => "✅",
                    AdminRiskLevel::Low => "🟢",
                    AdminRiskLevel::Medium => "🟡",
                    AdminRiskLevel::High => "🟠",
                    AdminRiskLevel::Critical => "🔴",
                };
                
                println!("\n{} Admin Risk: {:?}", risk_emoji, admin.risk_level);
                println!("💬 {}", admin.summary);
                
                // Store result
                results.push((name.to_string(), admin.risk_level, admin.summary.clone(), false));
            }
            Err(e) => {
                println!("Error!\n");
                println!("❌ Failed to analyze: {}", e);
                results.push((name.to_string(), AdminRiskLevel::Critical, format!("Analysis failed: {}", e), true));
            }
        }
        
        println!();
    }

    // Summary table
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                      SUMMARY REPORT                            ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");
    
    println!("{:<15} {:<12} {}", "TOKEN", "RISK LEVEL", "SUMMARY");
    println!("{}", "─".repeat(80));
    
    for (name, risk, summary, is_error) in &results {
        let risk_emoji = if *is_error {
            "❌"
        } else {
            match risk {
                AdminRiskLevel::None => "✅",
                AdminRiskLevel::Low => "🟢",
                AdminRiskLevel::Medium => "🟡",
                AdminRiskLevel::High => "🟠",
                AdminRiskLevel::Critical => "🔴",
            }
        };
        
        let truncated_summary = if summary.len() > 45 {
            format!("{}...", &summary[..42])
        } else {
            summary.to_string()
        };
        
        let risk_str = if *is_error {
            "ERROR".to_string()
        } else {
            format!("{:?}", risk)
        };
        
        println!("{} {:<13} {:<10} {}", risk_emoji, name, risk_str, truncated_summary);
    }
    
    // Statistics
    let none_count = results.iter().filter(|(_, r, _, e)| !e && matches!(r, AdminRiskLevel::None)).count();
    let low_count = results.iter().filter(|(_, r, _, e)| !e && matches!(r, AdminRiskLevel::Low)).count();
    let medium_count = results.iter().filter(|(_, r, _, e)| !e && matches!(r, AdminRiskLevel::Medium)).count();
    let high_count = results.iter().filter(|(_, r, _, e)| !e && matches!(r, AdminRiskLevel::High)).count();
    let critical_count = results.iter().filter(|(_, r, _, e)| !e && matches!(r, AdminRiskLevel::Critical)).count();
    let error_count = results.iter().filter(|(_, _, _, e)| *e).count();
    
    println!("\n{}", "─".repeat(80));
    println!("STATISTICS:");
    println!("  ✅ No Risk:       {} tokens", none_count);
    println!("  🟢 Low Risk:      {} tokens", low_count);
    println!("  🟡 Medium Risk:   {} tokens", medium_count);
    println!("  🟠 High Risk:     {} tokens", high_count);
    println!("  🔴 Critical Risk: {} tokens", critical_count);
    if error_count > 0 {
        println!("  ❌ Errors:        {} tokens", error_count);
    }
    println!("\n{}", "═".repeat(80));
    
    // Recommendations
    if high_count > 0 || critical_count > 0 {
        println!("\n⚠️  WARNING: {} token(s) have HIGH or CRITICAL admin risks!", 
                 high_count + critical_count);
        println!("   These tokens may be subject to rug pulls by active owners.");
        println!("   DO NOT INVEST without thorough research!\n");
    } else {
        println!("\n✅ All analyzed tokens have acceptable admin risk levels.\n");
    }

    Ok(())
}
