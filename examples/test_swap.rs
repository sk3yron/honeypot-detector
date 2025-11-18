use honeypot_detector::analyzers::SwapSimulator;
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter("honeypot_detector=info")
        .init();

    println!("🔍 PulseChain Honeypot Detector - Swap Test");
    println!("===========================================\n");

    // Connect to PulseChain
    println!("📡 Connecting to PulseChain RPC...");
    let client = Arc::new(BlockchainClient::new("https://rpc.pulsechain.com").await?);
    println!("✅ Connected to {}\n", client.chain_name());
    
    // Test token
    let token: ethers::types::Address = "0x1C81b4358246d3088Ab4361aB755F3D8D4dd62d2".parse()?;
    
    println!("🎯 Testing Token: {:?}", token);
    println!("Testing for potential honeypot patterns\n");
    
    // Run swap simulator
    let simulator = SwapSimulator::new(client);
    
    println!("🔄 Running swap simulations...\n");
    
    match simulator.test_swaps(token).await {
        Ok(result) => {
            println!("✅ Swap Tests Complete!");
            println!("========================\n");
            
            // Buy results
            println!("💰 BUY Tests:");
            if let Some(buy_micro) = &result.buy_micro {
                println!("  Micro (0.01%): {} - Tax: {:.2}% - Out: {}", 
                    if buy_micro.success { "✅" } else { "❌" },
                    buy_micro.tax_percent,
                    buy_micro.amount_out);
                if !buy_micro.success {
                    if let Some(reason) = &buy_micro.revert_reason {
                        println!("    ⚠️  Reason: {}", reason);
                    }
                }
            }
            if let Some(buy_normal) = &result.buy_normal {
                println!("  Normal (1%):   {} - Tax: {:.2}% - Out: {}", 
                    if buy_normal.success { "✅" } else { "❌" },
                    buy_normal.tax_percent,
                    buy_normal.amount_out);
                if !buy_normal.success {
                    if let Some(reason) = &buy_normal.revert_reason {
                        println!("    ⚠️  Reason: {}", reason);
                    }
                }
            }
            if let Some(buy_large) = &result.buy_large {
                println!("  Large (5%):    {} - Tax: {:.2}% - Out: {}", 
                    if buy_large.success { "✅" } else { "❌" },
                    buy_large.tax_percent,
                    buy_large.amount_out);
                if !buy_large.success {
                    if let Some(reason) = &buy_large.revert_reason {
                        println!("    ⚠️  Reason: {}", reason);
                    }
                }
            }
            println!("  Average Buy Tax: {:.2}%\n", result.avg_buy_tax);
            
            // Sell results
            println!("💸 SELL Tests:");
            if let Some(sell_micro) = &result.sell_micro {
                println!("  Micro (0.01%): {} - Tax: {:.2}%", 
                    if sell_micro.success { "✅" } else { "❌" },
                    sell_micro.tax_percent);
            }
            if let Some(sell_normal) = &result.sell_normal {
                println!("  Normal (1%):   {} - Tax: {:.2}%", 
                    if sell_normal.success { "✅" } else { "❌" },
                    sell_normal.tax_percent);
            }
            if let Some(sell_large) = &result.sell_large {
                println!("  Large (5%):    {} - Tax: {:.2}%", 
                    if sell_large.success { "✅" } else { "❌" },
                    sell_large.tax_percent);
                if !sell_large.success {
                    if let Some(reason) = &sell_large.revert_reason {
                        println!("    ⚠️  Reason: {}", reason);
                    }
                }
            }
            println!("  Average Sell Tax: {:.2}%\n", result.avg_sell_tax);
            
            // Pattern detection
            println!("🔍 PATTERN DETECTION:");
            println!("=====================");
            if result.has_overflow_trap {
                println!("🚨 U112 OVERFLOW TRAP DETECTED!");
                println!("   → Small trades work, large trades fail!");
                println!("   → This is YOUR discovered pattern! 🎉");
            } else {
                println!("✅ No U112 overflow detected");
            }
            
            if result.has_amount_limits {
                println!("⚠️  AMOUNT LIMITS DETECTED!");
                println!("   → Different amounts have different results");
            } else {
                println!("✅ No amount limits detected");
            }
            
            if result.avg_buy_tax > 25.0 || result.avg_sell_tax > 25.0 {
                println!("⚠️  HIGH TAXES DETECTED!");
                println!("   → Buy: {:.1}%, Sell: {:.1}%", result.avg_buy_tax, result.avg_sell_tax);
            }
            
            println!();
            println!("📊 VERDICT:");
            println!("===========");
            if result.has_overflow_trap {
                println!("🔴 HONEYPOT DETECTED - U112 OVERFLOW TRAP!");
                println!("   DO NOT BUY THIS TOKEN!");
            } else if result.has_amount_limits {
                println!("🔴 HONEYPOT DETECTED - AMOUNT LIMITS!");
                println!("   DO NOT BUY THIS TOKEN!");
            } else if result.is_suspicious() {
                println!("🟡 SUSPICIOUS - High risk, proceed with caution");
            } else {
                println!("🟢 Appears SAFE from swap analysis");
            }
        }
        Err(e) => {
            println!("❌ Error testing swaps: {}", e);
            println!("This could mean:");
            println!("  - No PulseX pair exists for this token");
            println!("  - RPC connection issues");
            println!("  - Token doesn't follow ERC20 standard");
            return Err(e.into());
        }
    }
    
    Ok(())
}
