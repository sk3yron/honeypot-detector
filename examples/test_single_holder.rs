use ethers::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://rpc.pulsechain.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let client = Arc::new(provider);
    
    let token: Address = "0x463413c579D29c26D59a65312657DFCe30D545A1".parse()?;
    let holder: Address = "0x4ad7f30c7f4c878b395d76c160ad1673bde73447".parse()?; // One that failed
    let wpls: Address = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27".parse()?;
    let router_v1: Address = "0xda9aba4eacf54e0273f56dffee6b8f1e20b23bba".parse()?;
    let router_v2: Address = "0x165C3410fC91EF562C50559f7d2289fEbed552d9".parse()?;
    
    // Check balance
    let balance_call = Bytes::from(hex::decode("70a08231000000000000000000000000").unwrap());
    let balance_call = [balance_call.to_vec(), holder.as_bytes().to_vec()].concat();
    
    let tx = TransactionRequest::new()
        .to(token)
        .data(Bytes::from(balance_call));
    
    let balance_result = client.call(&tx.into(), None).await?;
    let balance = U256::from_big_endian(&balance_result);
    
    println!("Holder: {:?}", holder);
    println!("Balance: {}", balance);
    
    // Try different amounts
    let test_amounts = vec![
        balance / 10000,  // 0.01%
        balance / 1000,   // 0.1%
        balance / 200,    // 0.5%
        balance / 100,    // 1%
    ];
    
    for (i, amount) in test_amounts.iter().enumerate() {
        if amount.is_zero() {
            println!("Amount {}: too small", i);
            continue;
        }
        
        println!("\nTesting {}% of balance: {}", 
            match i {
                0 => "0.01",
                1 => "0.1",
                2 => "0.5",
                3 => "1",
                _ => "?",
            },
            amount
        );
        
        // Test with V1 router
        println!("  Testing with PulseX V1...");
        let result = test_swap(&client, token, holder, wpls, router_v1, *amount).await;
        println!("    Result: {:?}", result);
        
        // Test with V2 router
        println!("  Testing with PulseX V2...");
        let result = test_swap(&client, token, holder, wpls, router_v2, *amount).await;
        println!("    Result: {:?}", result);
    }
    
    Ok(())
}

async fn test_swap(
    client: &Provider<Http>,
    token: Address,
    holder: Address,
    wpls: Address,
    router: Address,
    amount: U256,
) -> Result<U256, String> {
    // swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline)
    let mut calldata = hex::decode("38ed1739").unwrap(); // function selector
    
    // Encode parameters
    let mut amount_bytes = [0u8; 32];
    amount.to_big_endian(&mut amount_bytes);
    calldata.extend_from_slice(&amount_bytes);
    
    calldata.extend_from_slice(&[0u8; 32]); // amountOutMin = 0
    
    calldata.extend_from_slice(&[0u8; 28]); // offset to path array
    calldata.extend_from_slice(&[0, 0, 0, 0xa0u8]); // 160 in hex
    
    calldata.extend_from_slice(&[0u8; 28]); // pad recipient
    calldata.extend_from_slice(holder.as_bytes());
    
    calldata.extend_from_slice(&[255u8; 32]); // deadline = max
    
    // Path array length
    calldata.extend_from_slice(&[0u8; 31]);
    calldata.extend_from_slice(&[2u8]); // length = 2
    
    // Path[0] = token
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(token.as_bytes());
    
    // Path[1] = wpls
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(wpls.as_bytes());
    
    let tx = TransactionRequest::new()
        .from(holder)
        .to(router)
        .data(Bytes::from(calldata));
    
    match client.estimate_gas(&tx.into(), None).await {
        Ok(gas) => Ok(gas),
        Err(e) => Err(format!("{:?}", e)),
    }
}
