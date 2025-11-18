//! REVM state builder for PulseX swap simulation

use ethers::types::{Address, U256};
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, Bytes as RevmBytes,
    U256 as RevmU256, KECCAK_EMPTY,
};
use revm::InMemoryDB;
use crate::storage::calculate_mapping_slot;
use crate::utils::{DetectorError, Result};

/// Helper to convert ethers Address to REVM Address
pub fn to_revm_address(addr: Address) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}

/// Helper to convert ethers U256 to REVM U256
pub fn to_revm_u256(value: U256) -> RevmU256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    RevmU256::from_be_bytes(bytes)
}

/// Build REVM database state for swap simulation
pub struct StateBuilder {
    db: InMemoryDB,
}

impl StateBuilder {
    pub fn new() -> Self {
        Self {
            db: InMemoryDB::default(),
        }
    }
    
    /// Set up token contract
    pub fn with_token(
        mut self,
        address: Address,
        bytecode: &[u8],
    ) -> Self {
        let addr_revm = to_revm_address(address);
        let bytecode_obj = Bytecode::new_raw(RevmBytes::from(bytecode.to_vec()));
        
        let account = AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 1,
            code_hash: bytecode_obj.hash_slow(),
            code: Some(bytecode_obj),
        };
        
        self.db.insert_account_info(addr_revm, account);
        self
    }
    
    /// Set up pair contract
    pub fn with_pair(
        mut self,
        pair_address: Address,
        pair_bytecode: &[u8],
        reserve0: U256,
        reserve1: U256,
    ) -> Result<Self> {
        let pair_revm = to_revm_address(pair_address);
        let bytecode_obj = Bytecode::new_raw(RevmBytes::from(pair_bytecode.to_vec()));
        
        let account = AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 1,
            code_hash: bytecode_obj.hash_slow(),
            code: Some(bytecode_obj),
        };
        
        self.db.insert_account_info(pair_revm, account);
        
        // Set reserves in storage
        // UniswapV2Pair stores reserves at slot 8 as: uint112 reserve0, uint112 reserve1, uint32 timestamp
        // Packed into single slot: [reserve0 (112 bits)][reserve1 (112 bits)][timestamp (32 bits)]
        let packed_reserves = pack_reserves(reserve0, reserve1)?;
        let reserves_slot = RevmU256::from(8);
        
        self.db.insert_account_storage(pair_revm, reserves_slot, packed_reserves)
            .map_err(|e| DetectorError::SimulationError(format!("Failed to set reserves: {:?}", e)))?;
        
        Ok(self)
    }
    
    /// Set up router contract
    pub fn with_router(
        mut self,
        router_address: Address,
        router_bytecode: &[u8],
    ) -> Self {
        let router_revm = to_revm_address(router_address);
        let bytecode_obj = Bytecode::new_raw(RevmBytes::from(router_bytecode.to_vec()));
        
        let account = AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 1,
            code_hash: bytecode_obj.hash_slow(),
            code: Some(bytecode_obj),
        };
        
        self.db.insert_account_info(router_revm, account);
        self
    }
    
    /// Set up test wallet with PLS and token balance
    pub fn with_wallet(
        mut self,
        wallet: Address,
        pls_balance: U256,
        token_address: Address,
        token_balance: U256,
        token_balances_slot: u8,
    ) -> Result<Self> {
        let wallet_revm = to_revm_address(wallet);
        
        // Set PLS balance
        let account = AccountInfo {
            balance: to_revm_u256(pls_balance),
            nonce: 1,
            code_hash: KECCAK_EMPTY,
            code: None,
        };
        
        self.db.insert_account_info(wallet_revm, account);
        
        // Set token balance at correct storage slot
        let token_revm = to_revm_address(token_address);
        let balance_slot = calculate_mapping_slot(wallet, token_balances_slot);
        
        let mut slot_bytes = [0u8; 32];
        balance_slot.to_big_endian(&mut slot_bytes);
        let revm_slot = RevmU256::from_be_bytes(slot_bytes);
        
        self.db.insert_account_storage(
            token_revm,
            revm_slot,
            to_revm_u256(token_balance),
        ).map_err(|e| DetectorError::SimulationError(format!("Failed to set token balance: {:?}", e)))?;
        
        Ok(self)
    }
    
    /// Set allowance for router
    pub fn with_allowance(
        mut self,
        token_address: Address,
        owner: Address,
        spender: Address,
        amount: U256,
        allowances_slot: u8,
    ) -> Result<Self> {
        let token_revm = to_revm_address(token_address);
        
        // Calculate nested mapping slot: allowances[owner][spender]
        // First hash: keccak256(owner || allowances_slot)
        let owner_slot = calculate_mapping_slot(owner, allowances_slot);
        
        // Second hash: keccak256(spender || owner_slot)
        // We need to implement this properly
        let mut bytes = [0u8; 64];
        bytes[12..32].copy_from_slice(spender.as_bytes());
        let mut owner_slot_bytes = [0u8; 32];
        owner_slot.to_big_endian(&mut owner_slot_bytes);
        bytes[32..64].copy_from_slice(&owner_slot_bytes);
        
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(&bytes);
        let allowance_slot = U256::from_big_endian(&hash[..]);
        
        let mut slot_bytes = [0u8; 32];
        allowance_slot.to_big_endian(&mut slot_bytes);
        let revm_slot = RevmU256::from_be_bytes(slot_bytes);
        
        self.db.insert_account_storage(
            token_revm,
            revm_slot,
            to_revm_u256(amount),
        ).map_err(|e| DetectorError::SimulationError(format!("Failed to set allowance: {:?}", e)))?;
        
        Ok(self)
    }
    
    /// Build and return the database
    pub fn build(self) -> InMemoryDB {
        self.db
    }
}

impl Default for StateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pack reserves into single U256 (UniswapV2 format)
fn pack_reserves(reserve0: U256, reserve1: U256) -> Result<RevmU256> {
    // Check for U112 overflow
    let max_u112 = U256::from(2).pow(U256::from(112)) - 1;
    
    if reserve0 > max_u112 || reserve1 > max_u112 {
        return Err(DetectorError::SimulationError(
            format!("Reserve overflow: r0={}, r1={}, max={}", reserve0, reserve1, max_u112)
        ));
    }
    
    // Get current timestamp (use a fixed value for determinism)
    let timestamp: u32 = 1700000000; // Fixed timestamp for testing
    
    // Pack: [reserve0 (112 bits)][reserve1 (112 bits)][timestamp (32 bits)]
    let mut packed = [0u8; 32];
    
    // Reserve 0 at bytes 0-13 (14 bytes = 112 bits)
    let mut r0_bytes = [0u8; 32];
    reserve0.to_big_endian(&mut r0_bytes);
    packed[18..32].copy_from_slice(&r0_bytes[18..32]); // Last 14 bytes
    
    // Reserve 1 at bytes 14-27 (14 bytes = 112 bits)
    let mut r1_bytes = [0u8; 32];
    reserve1.to_big_endian(&mut r1_bytes);
    packed[4..18].copy_from_slice(&r1_bytes[18..32]); // Last 14 bytes
    
    // Timestamp at bytes 28-31 (4 bytes = 32 bits)
    let ts_bytes = timestamp.to_be_bytes();
    packed[0..4].copy_from_slice(&ts_bytes);
    
    Ok(RevmU256::from_be_bytes(packed))
}
