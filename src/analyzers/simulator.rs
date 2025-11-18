//! Simple REVM-based simulator - tests if tokens can actually be transferred
//! This is the most reliable honeypot detection method.
//! 
//! PHASE 2: Now uses storage layout detection to correctly set balances in REVM!
use std::sync::Arc;
use async_trait::async_trait;
use ethers::types::Address;
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, Bytes as RevmBytes, 
    TransactTo, U256 as RevmU256, KECCAK_EMPTY,
};
use revm::{EVM, InMemoryDB};
use crate::blockchain::BlockchainClient;
use crate::core::Analyzer;
use crate::models::{ContractTarget, AnalysisResult, Finding, Severity, Category};
use crate::utils::{DetectorError, Result};
use crate::storage::{LayoutDetector, calculate_mapping_slot};
use std::collections::HashMap;
/// Simple simulator that tests if token transfers work
pub struct SimulatorAnalyzer {
    client: Arc<BlockchainClient>,
}
impl SimulatorAnalyzer {
    pub fn new(client: Arc<BlockchainClient>) -> Self {
        Self { client }
    }
    
    /// Test if transfer() works - this is the key honeypot test
    /// PHASE 2: Now detects storage layout before testing!
    pub async fn test_transfer_direct(&self, token_address: Address) -> Result<TransferTest> {
        self.test_transfer(token_address).await
    }
    
    async fn test_transfer(&self, token_address: Address) -> Result<TransferTest> {
        tracing::info!("🔬 Testing transfer() for {:?}", token_address);
        
        // PHASE 2: Detect storage layout first
        let detector = LayoutDetector::new(self.client.clone());
        let layout_info = detector.detect(token_address).await?;
        
        tracing::info!(
            "📊 Detected storage layout: {} (slot {})", 
            layout_info.layout, 
            layout_info.balances_slot
        );
        
        // Get token bytecode
        let bytecode = self.client.get_bytecode(token_address).await?;
        
        // Setup test: try to transfer 1 token from address 0x1 to 0x2
        let from: Address = "0x0000000000000000000000000000000000000001".parse().unwrap();
        let to: Address = "0x0000000000000000000000000000000000000002".parse().unwrap();
        let amount = RevmU256::from(1_000_000_000_000_000_000u64); // 1 token (18 decimals)
        
        // Build calldata: transfer(address to, uint256 amount)
        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
        
        // Add 'to' address (32 bytes, left-padded)
        let mut to_bytes = [0u8; 32];
        to_bytes[12..32].copy_from_slice(to.as_bytes());
        calldata.extend_from_slice(&to_bytes);
        
        // Add amount (32 bytes)
        calldata.extend_from_slice(&amount.to_be_bytes::<32>());
        
        // Execute in REVM with detected storage layout
        let result = self.execute_in_revm(
            token_address,
            &bytecode,
            from,
            RevmBytes::from(calldata),
            layout_info.balances_slot, // PHASE 2: Pass storage slot
        ).await?;
        
        Ok(result)
    }
    
    /// Execute a transaction in REVM with pre-populated state
    /// PHASE 2: Now accepts balances_slot parameter for correct storage setup
    async fn execute_in_revm(
        &self,
        token_address: Address,
        bytecode: &[u8],
        caller: Address,
        calldata: RevmBytes,
        balances_slot: u8, // PHASE 2: Storage slot for balances mapping
    ) -> Result<TransferTest> {
        // Use InMemoryDB directly (no async calls during execution)
        let mut db = InMemoryDB::default();
        
        // Convert addresses
        let token_revm = to_revm_address(token_address);
        let caller_revm = to_revm_address(caller);
        
        // Setup token contract account
        let bytecode_obj = Bytecode::new_raw(RevmBytes::from(bytecode.to_vec()));
        let token_account = AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 1,
            code_hash: bytecode_obj.hash_slow(),
            code: Some(bytecode_obj),
        };
        db.insert_account_info(token_revm, token_account);
        
        // Setup caller account with PLS balance
        let caller_account = AccountInfo {
            balance: RevmU256::from(10_000_000_000_000_000_000u128), // 10 PLS
            nonce: 1,
            code_hash: KECCAK_EMPTY,
            code: None,
        };
        db.insert_account_info(caller_revm, caller_account);
        
        // Setup recipient account
        let to: Address = "0x0000000000000000000000000000000000000002".parse().unwrap();
        let to_revm = to_revm_address(to);
        let to_account = AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: None,
        };
        db.insert_account_info(to_revm, to_account);
        
        // PHASE 2 FIX: Give caller tokens in storage with CORRECT slot calculation
        // We calculate the actual storage slot using keccak256(address || slot)
        
        // Step 1: Calculate the storage slot for caller's balance
        let caller_balance_slot = calculate_mapping_slot(caller, balances_slot);
        
        // Step 2: Convert ethers::U256 to REVM U256
        let mut slot_bytes = [0u8; 32];
        caller_balance_slot.to_big_endian(&mut slot_bytes);
        let revm_slot = RevmU256::from_be_bytes(slot_bytes);
        
        // Step 3: Set balance at the CORRECT calculated slot
        let token_balance = RevmU256::from(1000_000_000_000_000_000_000u128); // 1000 tokens
        db.insert_account_storage(token_revm, revm_slot, token_balance)
            .map_err(|e| DetectorError::SimulationError(format!("Storage error: {:?}", e)))?;
        
        tracing::debug!(
            "✅ PHASE 2: Set balance {} for caller {:?} at slot {:?} (base slot: {})",
            token_balance,
            caller,
            revm_slot,
            balances_slot
        );
        
        // Create EVM instance
        let mut evm = EVM::new();
        evm.database(db);
        
        // Configure transaction environment
        evm.env.tx.caller = caller_revm;
        evm.env.tx.transact_to = TransactTo::Call(token_revm);
        evm.env.tx.data = calldata;
        evm.env.tx.value = RevmU256::ZERO;
        evm.env.tx.gas_limit = 500_000;
        evm.env.tx.gas_price = RevmU256::from(1_000_000_000u64);
        
        // Execute transaction
        let exec_result = evm.transact_commit()
            .map_err(|e| DetectorError::SimulationError(format!("REVM exec failed: {:?}", e)))?;
        
        // Parse result
        use revm::primitives::{ExecutionResult, Output};
        
        match exec_result {
            ExecutionResult::Success { gas_used, output, logs, .. } => {
                // Check return value
                let returns_true = match &output {
                    Output::Call(data) => {
                        !data.is_empty() && (data[data.len() - 1] == 1 || data.get(31) == Some(&1))
                    }
                    _ => false,
                };
                
                // Check for Transfer event
                let has_event = logs.iter().any(|log| {
                    !log.topics.is_empty() && 
                    log.topics[0].0 == TRANSFER_EVENT_SIGNATURE
                });
                
                tracing::info!(
                    "✅ Transfer executed: returns={}, event={}, gas={}",
                    returns_true, has_event, gas_used
                );
                
                Ok(TransferTest {
                    success: true,
                    returns_true,
                    has_transfer_event: has_event,
                    gas_used,
                    revert_reason: None,
                })
            }
            ExecutionResult::Revert { gas_used, output } => {
                let reason = parse_revert(&output);
                tracing::warn!("❌ Transfer reverted: {}", reason);
                
                Ok(TransferTest {
                    success: false,
                    returns_true: false,
                    has_transfer_event: false,
                    gas_used,
                    revert_reason: Some(reason),
                })
            }
            ExecutionResult::Halt { reason, gas_used } => {
                tracing::warn!("⛔ Transfer halted: {:?}", reason);
                
                Ok(TransferTest {
                    success: false,
                    returns_true: false,
                    has_transfer_event: false,
                    gas_used,
                    revert_reason: Some(format!("Halted: {:?}", reason)),
                })
            }
        }
    }
}
#[async_trait]
impl Analyzer for SimulatorAnalyzer {
    fn name(&self) -> &'static str {
        "revm-simulator"
    }
    
    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
        // Only run on PulseChain
        if self.client.chain_id() != 369 {
            tracing::warn!("Simulator only supports PulseChain (chain 369)");
            return Ok(AnalysisResult {
                risk_score: 0,
                findings: vec![],
                metadata: HashMap::new(),
            });
        }
        
        // Need bytecode
        if target.bytecode.is_none() {
            return Ok(AnalysisResult {
                risk_score: 0,
                findings: vec![],
                metadata: HashMap::new(),
            });
        }
        
        tracing::info!("🔍 Running REVM simulation for {:?}", target.address);
        
        // Test transfer
        let test_result = self.test_transfer(target.address).await?;
        
        // Analyze results
        let mut findings = Vec::new();
        let mut risk_score = 0u32;
        
        // CRITICAL: Transfer fails = HONEYPOT
        if !test_result.success {
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::Honeypot,
                message: "🚨 HONEYPOT: transfer() transaction REVERTED".to_string(),
                evidence: Some(serde_json::json!({
                    "revert_reason": test_result.revert_reason,
                    "gas_used": test_result.gas_used,
                })),
            });
            risk_score = 100;
        }
        // CRITICAL: Returns true but no event = FAKE
        else if test_result.returns_true && !test_result.has_transfer_event {
            findings.push(Finding {
                severity: Severity::Critical,
                category: Category::Honeypot,
                message: "🚨 HONEYPOT: transfer() returns true but NO Transfer event".to_string(),
                evidence: Some(serde_json::json!({
                    "returns": true,
                    "event_emitted": false,
                    "description": "Fake return value - tokens don't actually move"
                })),
            });
            risk_score = 100;
        }
        // SUCCESS: Transfer works properly
        else if test_result.returns_true && test_result.has_transfer_event {
            findings.push(Finding {
                severity: Severity::Info,
                category: Category::Simulation,
                message: "✅ Transfer simulation PASSED".to_string(),
                evidence: Some(serde_json::json!({
                    "gas_used": test_result.gas_used,
                })),
            });
            risk_score = 0;
        }
        
        let mut metadata = HashMap::new();
        metadata.insert("can_transfer".to_string(), serde_json::json!(test_result.success));
        metadata.insert("transfer_gas".to_string(), serde_json::json!(test_result.gas_used));
        
        Ok(AnalysisResult {
            risk_score: risk_score.min(100) as u8,
            findings,
            metadata,
        })
    }
    
    fn weight(&self) -> f64 {
        0.60 // 60% weight - simulation is most reliable
    }
    
    fn can_analyze(&self, target: &ContractTarget) -> bool {
        target.bytecode.is_some()
    }
}
// ============================================================================
// Helper Types & Functions
// ============================================================================
/// Result of transfer test
#[derive(Debug)]
pub struct TransferTest {
    pub success: bool,
    pub returns_true: bool,
    pub has_transfer_event: bool,
    pub gas_used: u64,
    pub revert_reason: Option<String>,
}
/// Transfer event signature: keccak256("Transfer(address,address,uint256)")
const TRANSFER_EVENT_SIGNATURE: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
    0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];
fn to_revm_address(addr: Address) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}
fn parse_revert(output: &RevmBytes) -> String {
    if output.is_empty() {
        return "No reason".to_string();
    }
    
    // Check for Error(string) signature
    if output.len() > 68 && &output[0..4] == &[0x08, 0xc3, 0x79, 0xa0] {
        if let Ok(msg) = String::from_utf8(output[68..].to_vec()) {
            return msg.trim_end_matches('\0').to_string();
        }
    }
    
    format!("0x{}", hex::encode(&output[..output.len().min(32)]))
}
