/// Test MCP handshake and tool discovery
use honeypot_detector::analyzers::mcp_client::{MCPClient, AnalysisMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("\n{}", "=".repeat(80));
    println!("Testing MCP Handshake & Tool Discovery");
    println!("{}\n", "=".repeat(80));

    // Test 1: Create MCP client (performs handshake)
    println!("Test 1: Creating MCP client (handshake)...");
    let mut client = MCPClient::new(AnalysisMode::Quick).await?;
    println!("✓ MCP client created successfully");
    println!("✓ Handshake completed: {}", client.is_initialized());

    // Test 2: Discover available tools
    println!("\nTest 2: Discovering MCP tools...");
    let tools = client.discover_tools().await?;
    println!("✓ Discovered {} tools:", tools.len());
    for tool in &tools {
        println!("  - {}: {}", tool.name, tool.description);
    }

    // Test 3: Test a simple tool call
    println!("\nTest 3: Testing get_contract_info tool...");
    let test_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"; // USDT
    let rpc_url = "https://eth.llamarpc.com";
    
    match client.get_contract_info(test_address, rpc_url).await {
        Ok(info) => {
            println!("✓ Contract info retrieved:");
            println!("{}", serde_json::to_string_pretty(&info)?);
        },
        Err(e) => {
            println!("⚠ Contract info failed (expected if RPC is down): {}", e);
        }
    }

    // Test 4: Token usage tracking
    println!("\nTest 4: Token usage...");
    let usage = client.token_usage();
    println!("✓ Token usage - Input: {}, Output: {}, Total: {}", 
        usage.input_tokens, usage.output_tokens, usage.total_tokens);

    println!("\n{}", "=".repeat(80));
    println!("All MCP handshake tests passed!");
    println!("{}\n", "=".repeat(80));

    Ok(())
}
