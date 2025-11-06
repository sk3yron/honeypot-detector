use honeypot_detector::*;
use honeypot_detector::blockchain::BlockchainClient;
use honeypot_detector::analyzers::StaticAnalyzer;
use std::env;
use std::sync::Arc;

#[cfg(feature = "ml-inference")]
use honeypot_detector::analyzers::MLAnalyzer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();
    
    // Parse arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <token_address> [rpc_url]", args[0]);
        eprintln!("\nExamples:");
        eprintln!("  {} 0xA1077a294dDE1B09bB078844df40758a5D0f9a27", args[0]);
        eprintln!("  {} 0xA1077a294dDE1B09bB078844df40758a5D0f9a27 https://rpc.pulsechain.com", args[0]);
        std::process::exit(1);
    }
    
    let address_str = &args[1];
    let rpc_url = args.get(2)
        .map(|s| s.as_str())
        .unwrap_or("https://rpc.pulsechain.com");
    
    println!("🔍 Honeypot Detector v0.2.0");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // Parse address
    let address: ethers::types::Address = address_str.parse()
        .map_err(|_| DetectorError::InvalidAddress(address_str.to_string()))?;
    
    println!("Address: {:?}", address);
    
    // Connect to blockchain
    println!("Connecting to {}...", rpc_url);
    let client = BlockchainClient::new(rpc_url).await?;
    println!("✓ Connected to {}\n", client.chain_name());
    
    // Check if it's a contract
    if !client.is_contract(address).await? {
        eprintln!("❌ Address is not a contract!");
        std::process::exit(1);
    }
    
    // Fetch bytecode
    println!("Fetching bytecode...");
    let bytecode = client.get_bytecode(address).await?;
    println!("✓ Bytecode fetched: {} bytes\n", bytecode.len());
    
    // Create target with bytecode
    let target = ContractTarget::new(address)
        .with_bytecode(bytecode);
    
    // Create detector with analyzers
    let mut detector = HoneypotDetector::new();
    
    // Always add static analyzer
    println!("Loading analyzers...");
    detector = detector.add_analyzer(Arc::new(StaticAnalyzer::new()));
    println!("✓ Static analyzer loaded");
    
    // Optionally add ML analyzer
    #[cfg(feature = "ml-inference")]
    {
        match MLAnalyzer::new("./models") {
            Ok(ml_analyzer) => {
                detector = detector.add_analyzer(Arc::new(ml_analyzer));
                println!("✓ ML analyzer loaded");
            }
            Err(e) => {
                eprintln!("⚠️  Warning: Could not load ML model: {}", e);
                eprintln!("   Continuing with static analysis only");
            }
        }
    }
    
    println!();
    println!("Running analysis...\n");
    
    // Detect
    let verdict = detector.detect(target).await?;
    
    // Print result
    println!("{}", verdict);
    
    // Exit code based on result
    if verdict.is_honeypot {
        std::process::exit(1);
    }
    
    Ok(())
}
