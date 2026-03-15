use honeypot_detector::analyzers::swap::{ApprovedHolderSimulator, AdminRiskLevel, FailureType};
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();

    // Tokens from user's list (all 15 tokens with improved quarter-based scanning)
    let tokens = vec![
        ("0x463413c579D29c26D59a65312657DFCe30D545A1", "TREASURY BILL"),
        ("0x1D177CB9EfEEa49A8B97ab1C72785a3A37ABc9Ff", "FD"),
        ("0x812571A12330A74E2A3C1fF8953f6f3aac7a83e9", "FDC"),
        ("0x51160F352ED148C89d48dfe6384Edd07aFA24E0E", "DFM"),
        ("0xe37acc54711562510fafc45d8199ee329ebbcedd", "PARADE"),
        ("0xC7145e1290B1d1221Aba5Ae48d4aCE17c6BE088F", "Tellerz"),
        ("0x6a8ee78653c588530d31fa308f4b165f346bd9e0", "Token"),
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
    println!("║      FULL HONEYPOT DETECTION - {} TOKENS                    ║", tokens.len());
    println!("║      (Admin Check + Holder Simulation + U112 Detection)       ║");
    println!("║      WITH IMPROVED QUARTER-BASED SCANNING & PITEAS ROUTER     ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");
    println!("⏱️  This will take several minutes as it simulates real trades...\n");

    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    let simulator = ApprovedHolderSimulator::new(client);

    struct TokenResult {
        name: String,
        is_honeypot: bool,
        admin_risk: AdminRiskLevel,
        confidence: f64,
        message: String,
        tested_holders: usize,
        has_overflow: bool,
        error: Option<String>,
    }

    let mut results = Vec::new();

    for (i, (addr, name)) in tokens.iter().enumerate() {
        println!("╔════════════════════════════════════════════════════════════════╗");
        println!("║ Token {}/{}  -  {}                                              ║", i + 1, tokens.len(), name);
        println!("╚════════════════════════════════════════════════════════════════╝");
        println!("Address: {}\n", addr);
        
        let token: ethers::types::Address = match addr.parse() {
            Ok(t) => t,
            Err(e) => {
                println!("❌ Invalid address: {}\n", e);
                results.push(TokenResult {
                    name: name.to_string(),
                    is_honeypot: true,
                    admin_risk: AdminRiskLevel::Critical,
                    confidence: 0.0,
                    message: format!("Invalid address: {}", e),
                    tested_holders: 0,
                    has_overflow: false,
                    error: Some(format!("Invalid address: {}", e)),
                });
                continue;
            }
        };
        
        // Run FULL honeypot detection (admin + holder simulation)
        print!("🔍 Running complete honeypot analysis... ");
        match simulator.run_complete_test(token).await {
            Ok(verdict) => {
                println!("Done!\n");
                
                // Check for U112 overflow in failure types
                let has_overflow = verdict.failure_types.iter().any(|ft| {
                    if let FailureType::MathOverflow(msg) = ft {
                        msg.to_lowercase().contains("overflow") || msg.to_lowercase().contains("lok")
                    } else {
                        false
                    }
                });
                
                // Display results
                println!("📊 RESULTS:");
                println!("   • Holders tested: {}", verdict.tested_holders);
                println!("   • Successful sells: {}", verdict.successful_sells);
                println!("   • Failed sells: {}", verdict.failed_sells);
                
                if has_overflow {
                    println!("   • ⚠️  U112 OVERFLOW DETECTED!");
                }
                
                // Admin risks
                if let Some(ref admin) = verdict.admin_risks {
                    let risk_emoji = match admin.risk_level {
                        AdminRiskLevel::None => "✅",
                        AdminRiskLevel::Low => "🟢",
                        AdminRiskLevel::Medium => "🟡",
                        AdminRiskLevel::High => "🟠",
                        AdminRiskLevel::Critical => "🔴",
                    };
                    println!("\n{} Admin Risk: {:?}", risk_emoji, admin.risk_level);
                    if admin.risk_level as u8 >= 2 {
                        println!("   {}", admin.summary);
                    }
                }
                
                // Honeypot verdict
                println!("\n{} VERDICT: {}", 
                    if verdict.is_honeypot { "🔴" } else { "✅" },
                    if verdict.is_honeypot { "HONEYPOT DETECTED!" } else { "SAFE" }
                );
                println!("   Confidence: {:.0}%", verdict.confidence * 100.0);
                println!("   Message: {}\n", verdict.message);
                
                // Show failure details if honeypot
                if verdict.is_honeypot && !verdict.failure_types.is_empty() {
                    println!("⚠️  Failure Analysis:");
                    let mut overflow_count = 0;
                    let mut blocked_count = 0;
                    let mut other_count = 0;
                    
                    for ft in &verdict.failure_types {
                        match ft {
                            FailureType::MathOverflow(_) => {
                                overflow_count += 1;
                            }
                            FailureType::TransferBlocked(_) => {
                                blocked_count += 1;
                            }
                            FailureType::CustomError(_) => {
                                other_count += 1;
                            }
                            _ => {}
                        }
                    }
                    
                    if overflow_count > 0 {
                        println!("   • Math Overflow errors: {} (likely U112 trap!)", overflow_count);
                    }
                    if blocked_count > 0 {
                        println!("   • Transfer blocked: {}", blocked_count);
                    }
                    if other_count > 0 {
                        println!("   • Custom errors: {}", other_count);
                    }
                    println!();
                }
                
                results.push(TokenResult {
                    name: name.to_string(),
                    is_honeypot: verdict.is_honeypot,
                    admin_risk: verdict.admin_risks.as_ref()
                        .map(|a| a.risk_level)
                        .unwrap_or(AdminRiskLevel::None),
                    confidence: verdict.confidence,
                    message: verdict.message.clone(),
                    tested_holders: verdict.tested_holders,
                    has_overflow,
                    error: None,
                });
            }
            Err(e) => {
                println!("Error!\n");
                println!("❌ Analysis failed: {}\n", e);
                
                results.push(TokenResult {
                    name: name.to_string(),
                    is_honeypot: false,
                    admin_risk: AdminRiskLevel::None,
                    confidence: 0.0,
                    message: format!("Analysis failed: {}", e),
                    tested_holders: 0,
                    has_overflow: false,
                    error: Some(e.to_string()),
                });
            }
        }
        
        println!("{}", "═".repeat(68));
        println!();
    }

    // Final Summary Report
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                   FINAL SUMMARY REPORT                         ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");
    
    println!("{:<18} {:<12} {:<10} {}", "TOKEN", "STATUS", "TESTED", "ISSUE");
    println!("{}", "─".repeat(80));
    
    for result in &results {
        let status_emoji = if result.error.is_some() {
            "❓"
        } else if result.is_honeypot {
            "🔴"
        } else {
            "✅"
        };
        
        let status = if result.error.is_some() {
            "ERROR"
        } else if result.is_honeypot {
            "HONEYPOT"
        } else {
            "SAFE"
        };
        
        let issue = if result.has_overflow {
            "U112 OVERFLOW!"
        } else if result.is_honeypot {
            "Transfer blocked"
        } else if result.error.is_some() {
            "Analysis error"
        } else {
            "None"
        };
        
        println!("{} {:<16} {:<10} {:<7} {}", 
            status_emoji, 
            result.name, 
            status,
            result.tested_holders,
            issue
        );
    }
    
    // Statistics
    let safe_count = results.iter().filter(|r| !r.is_honeypot && r.error.is_none()).count();
    let honeypot_count = results.iter().filter(|r| r.is_honeypot).count();
    let overflow_count = results.iter().filter(|r| r.has_overflow).count();
    let error_count = results.iter().filter(|r| r.error.is_some()).count();
    
    println!("\n{}", "─".repeat(80));
    println!("STATISTICS:");
    println!("  ✅ Safe tokens:          {}/{}", safe_count, tokens.len());
    println!("  🔴 Honeypots detected:   {}/{}", honeypot_count, tokens.len());
    println!("  ⚠️  U112 overflow traps: {}/{}", overflow_count, tokens.len());
    if error_count > 0 {
        println!("  ❓ Analysis errors:      {}/{}", error_count, tokens.len());
    }
    
    println!("\n{}", "═".repeat(80));
    
    // Critical warnings
    if overflow_count > 0 {
        println!("\n⚠️  CRITICAL WARNING: {} TOKEN(S) HAVE U112 OVERFLOW TRAPS!", overflow_count);
        println!("   These tokens are paired with BAR token which has maxed uint112 reserves.");
        println!("   You CANNOT sell these tokens - the swap will always revert!");
        println!("   This is a SOPHISTICATED HONEYPOT mechanism.\n");
        
        println!("   Affected tokens:");
        for result in &results {
            if result.has_overflow {
                println!("   🔴 {} - DO NOT BUY!", result.name);
            }
        }
        println!();
    }
    
    if honeypot_count > 0 {
        println!("\n⚠️  {} HONEYPOT(S) DETECTED - DO NOT TRADE THESE TOKENS!\n", honeypot_count);
    } else if safe_count == tokens.len() {
        println!("\n✅ All analyzed tokens passed honeypot detection!\n");
    }

    Ok(())
}
