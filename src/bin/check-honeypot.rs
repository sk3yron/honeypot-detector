use honeypot_detector::analyzers::{ApprovedHolderSimulator, FailureType};
use honeypot_detector::blockchain::BlockchainClient;
use std::sync::Arc;
use clap::Parser;

/// PulseChain Honeypot Detector - Check if a token is a honeypot
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Token contract address to check
    #[arg(value_name = "TOKEN_ADDRESS")]
    token: String,

    /// PulseChain RPC URL
    #[arg(short, long, default_value = "https://rpc.pulsechain.com")]
    rpc: String,

    /// Show verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Setup logging
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("honeypot_detector=debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("honeypot_detector=info")
            .init();
    }

    println!("\n🔍 PulseChain Honeypot Detector");
    println!("================================\n");

    // Parse token address
    let token: ethers::types::Address = args.token.parse()
        .map_err(|e| format!("Invalid token address: {}", e))?;

    println!("🎯 Token: {}", token);
    println!("📡 RPC: {}\n", args.rpc);

    // Connect to RPC
    print!("Connecting to PulseChain... ");
    let client = Arc::new(BlockchainClient::new(&args.rpc).await?);
    println!("✅ Connected to {}", client.chain_name());

    // Run simulation
    println!("\n🚀 Running approved holder simulation...\n");
    let simulator = ApprovedHolderSimulator::new(client);

    match simulator.run_complete_test(token).await {
        Ok(verdict) => {
            println!("╔══════════════════════════════════════════════════════╗");
            println!("║              SIMULATION RESULTS                      ║");
            println!("╚══════════════════════════════════════════════════════╝\n");

            println!("📊 Statistics:");
            println!("   • Holders tested: {}", verdict.tested_holders);
            println!("   • Successful sells: {}", verdict.successful_sells);
            println!("   • Failed sells: {}", verdict.failed_sells);

            if !verdict.failure_types.is_empty() && args.verbose {
                println!("\n⚠️  Failure types:");
                for (i, failure) in verdict.failure_types.iter().enumerate() {
                    match failure {
                        FailureType::NeedsApproval => {
                            println!("   {}. Needs Approval (not a honeypot)", i + 1);
                        }
                        FailureType::InsufficientBalance => {
                            println!("   {}. Insufficient Balance (not a honeypot)", i + 1);
                        }
                        FailureType::InsufficientLiquidity(msg) => {
                            println!("   {}. Insufficient Liquidity (not a honeypot): {}", i + 1, msg);
                        }
                        FailureType::MathOverflow(msg) => {
                            println!("   {}. Math Overflow: {}", i + 1, msg);
                        }
                        FailureType::TransferBlocked(msg) => {
                            println!("   {}. Transfer Blocked: {}", i + 1, msg);
                        }
                        FailureType::CustomError(msg) => {
                            println!("   {}. Custom Error: {}", i + 1, msg);
                        }
                        FailureType::Unknown(msg) => {
                            println!("   {}. Unknown Error: {}", i + 1, msg);
                        }
                    }
                }
            }

            // Show admin risk analysis if available
            if let Some(ref admin) = verdict.admin_risks {
                println!("\n╔══════════════════════════════════════════════════════╗");
                println!("║              ADMIN RISK ANALYSIS                     ║");
                println!("╚══════════════════════════════════════════════════════╝\n");
                
                println!("🔒 Admin Privileges Detected:");
                if admin.has_mint {
                    println!("   • Mint function: YES");
                }
                if admin.has_burn {
                    println!("   • Burn function: YES");
                }
                if admin.has_pause {
                    println!("   • Pause function: YES");
                }
                if admin.has_blacklist {
                    println!("   • Blacklist function: YES");
                }
                
                if admin.has_owner {
                    if let Some(owner) = admin.owner_address {
                        println!("\n👤 Owner: {}", owner);
                        if admin.is_renounced {
                            println!("   ✅ Status: RENOUNCED (safe)");
                        } else {
                            println!("   ⚠️  Status: ACTIVE (can execute admin functions)");
                        }
                    }
                }
                
                println!("\n📊 Risk Level: {:?}", admin.risk_level);
                println!("💬 {}", admin.summary);
            }

            println!("\n╔══════════════════════════════════════════════════════╗");
            println!("║                    VERDICT                           ║");
            println!("╚══════════════════════════════════════════════════════╝\n");

            if verdict.is_honeypot {
                println!("🔴 HONEYPOT DETECTED!");
                println!("   ⚠️  DO NOT BUY THIS TOKEN!");
            } else {
                println!("🟢 Token appears SAFE");
            }

            println!("\n📈 Confidence: {:.0}%", verdict.confidence * 100.0);
            println!("💬 Message: {}\n", verdict.message);

            // Exit code: 0 = safe, 1 = honeypot, 2 = uncertain
            if verdict.is_honeypot {
                std::process::exit(1);
            } else if verdict.confidence < 0.5 {
                std::process::exit(2);
            } else {
                std::process::exit(0);
            }
        }
        Err(e) => {
            println!("\n❌ Error running simulation: {}\n", e);
            println!("Possible reasons:");
            println!("  • RPC connection issues");
            println!("  • Invalid token address");
            println!("  • Token doesn't exist");
            println!("  • No trading pair on PulseX");
            println!("  • No trading activity (no approved holders)\n");
            std::process::exit(3);
        }
    }
}
