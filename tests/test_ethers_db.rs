use honeypot_detector::blockchain::{BlockchainClient, EthersDB};
use std::sync::Arc;

#[tokio::test]
async fn test_ethers_db_integration() {
    // Connect to PulseChain
    let client = Arc::new(
        BlockchainClient::new("https://rpc.pulsechain.com")
            .await
            .expect("Failed to connect to RPC")
    );
    
    // Create EthersDB
    let db = EthersDB::new(client.clone()).expect("Failed to create EthersDB");
    
    println!("✅ EthersDB created successfully");
    println!("Connected to chain: {}", client.chain_name());
}

#[tokio::test]
async fn test_state_fetching() {
    let client = Arc::new(
        BlockchainClient::new("https://rpc.pulsechain.com")
            .await
            .expect("Failed to connect")
    );
    
    let mut db = EthersDB::new(client).expect("Failed to create DB");
    
    // Test fetching WPLS contract
    let wpls: ethers::types::Address = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27"
        .parse()
        .unwrap();
    
    use revm::primitives::Address as RevmAddress;
    let wpls_revm = RevmAddress::from_slice(wpls.as_bytes());
    
    use revm::Database;
    let account = db.basic(wpls_revm).expect("Failed to fetch account");
    
    assert!(account.is_some());
    let account = account.unwrap();
    
    println!("✅ Successfully fetched WPLS account");
    println!("   Balance: {}", account.balance);
    println!("   Nonce: {}", account.nonce);
    println!("   Has code: {}", account.code.is_some());
}
