//! EthersDB - REVM Database implementatin that fetches state from RPC
//! Optimized for PulseChain simulation
use std::collections::HashMap;
use std::sync::Arc;
use ethers::prelude::*;
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, Bytes as RevmBytes, 
    B256, U256 as RevmU256, KECCAK_EMPTY,
};
use revm::{Database, DatabaseCommit};
use crate::blockchain::BlockchainClient;
use crate::utils::{DetectorError, Result};
/// Database implementation that fetches state from PulseChain RPC
pub struct EthersDB {
    /// RPC client for fetching blockchain state
    client: Arc<BlockchainClient>,
    
    /// Cached account information
    accounts: HashMap<RevmAddress, AccountInfo>,
    
    /// Cached storage slots
    storage: HashMap<(RevmAddress, RevmU256), RevmU256>,
    
    /// Runtime handle for executing async RPC calls synchronously
    runtime_handle: tokio::runtime::Handle,
}
impl EthersDB {
    /// Create a new EthersDB instance
    pub fn new(client: Arc<BlockchainClient>) -> Result<Self> {
        // Get or create runtime handle
        let runtime_handle = tokio::runtime::Handle::try_current()
            .map_err(|_| DetectorError::SimulationError(
                "No tokio runtime found. EthersDB requires async runtime.".into()
            ))?;
        
        Ok(Self {
            client,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            runtime_handle,
        })
    }
    
    /// Insert a pre-configured account (useful for test setups)
    pub fn insert_account(&mut self, address: RevmAddress, account: AccountInfo) {
        self.accounts.insert(address, account);
    }
    
    /// Insert pre-configured storage (useful for test setups)
    pub fn insert_storage(&mut self, address: RevmAddress, slot: RevmU256, value: RevmU256) {
        self.storage.insert((address, slot), value);
    }
    
    /// Convert ethers Address to REVM Address
    fn to_revm_address(addr: Address) -> RevmAddress {
        RevmAddress::from_slice(addr.as_bytes())
    }
    
    /// Convert REVM Address to ethers Address
    fn to_ethers_address(addr: RevmAddress) -> Address {
        Address::from_slice(addr.as_slice())
    }
    
    /// Fetch account info from RPC (blocking call)
    fn fetch_account_from_rpc(&self, address: RevmAddress) -> Result<AccountInfo> {
        let eth_address = Self::to_ethers_address(address);
        
        // Block on async RPC call
        let result = self.runtime_handle.block_on(async {
            // Get balance
            let balance = self.client.provider.get_balance(eth_address, None).await?;
            
            // Get nonce
            let nonce = self.client.provider.get_transaction_count(eth_address, None).await?;
            
            // Get code
            let code = self.client.provider.get_code(eth_address, None).await?;
            
            Ok::<(U256, U256, Bytes), ProviderError>((balance, nonce, code))
        }).map_err(|e: ProviderError| DetectorError::RpcError(e))?;
        
        let (balance, nonce, code) = result;
        
        // Convert balance: ethers U256 to REVM U256
        let balance_revm = RevmU256::from_limbs(balance.0);
        let nonce_revm = nonce.as_u64();
        
        // Process bytecode
        let (code_hash, bytecode) = if code.is_empty() {
            (KECCAK_EMPTY, None)
        } else {
            let bytecode = Bytecode::new_raw(RevmBytes::from(code.to_vec()));
            let code_hash = bytecode.hash_slow();
            (code_hash, Some(bytecode))
        };
        
        Ok(AccountInfo {
            balance: balance_revm,
            nonce: nonce_revm,
            code_hash,
            code: bytecode,
        })
    }
    
    /// Fetch storage slot from RPC (blocking call)
    fn fetch_storage_from_rpc(&self, address: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let eth_address = Self::to_ethers_address(address);
        
        // Convert REVM U256 to ethers H256 for storage slot
        let slot_bytes = index.to_be_bytes::<32>();
        let slot = H256::from(slot_bytes);
        
        // Block on async RPC call
        let value = self.runtime_handle.block_on(async {
            self.client.provider.get_storage_at(eth_address, slot, None).await
        }).map_err(DetectorError::RpcError)?;
        
        // Convert H256 to REVM U256
        Ok(RevmU256::from_be_bytes(value.0))
    }
}
impl Database for EthersDB {
    type Error = DetectorError;
    
    /// Get basic account information
    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>> {
        // Check cache first
        if let Some(account) = self.accounts.get(&address) {
            tracing::trace!("Cache hit for account {:?}", address);
            return Ok(Some(account.clone()));
        }
        
        tracing::debug!("Fetching account {:?} from RPC", address);
        
        // Fetch from RPC
        let account = self.fetch_account_from_rpc(address)?;
        
        // Cache it
        self.accounts.insert(address, account.clone());
        
        Ok(Some(account))
    }
    
    /// Get code by hash
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode> {
        // If empty hash, return empty bytecode
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        
        // Search in cached accounts
        for account in self.accounts.values() {
            if account.code_hash == code_hash {
                if let Some(ref code) = account.code {
                    return Ok(code.clone());
                }
            }
        }
        
        // If not found, return empty (we should have loaded it via basic())
        tracing::warn!("Code hash {:?} not found in cache", code_hash);
        Ok(Bytecode::new())
    }
    
    /// Get storage value at slot
    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let key = (address, index);
        
        // Check cache first
        if let Some(value) = self.storage.get(&key) {
            tracing::trace!("Cache hit for storage {:?}[{:?}]", address, index);
            return Ok(*value);
        }
        
        tracing::debug!("Fetching storage {:?}[{:?}] from RPC", address, index);
        
        // Fetch from RPC
        let value = self.fetch_storage_from_rpc(address, index)?;
        
        // Cache it
        self.storage.insert(key, value);
        
        Ok(value)
    }
    
    /// Get block hash by number
    fn block_hash(&mut self, number: RevmU256) -> Result<B256> {
        let block_number = number.to::<u64>();
        
        // Block on async RPC call
        let block = self.runtime_handle.block_on(async {
            self.client.provider.get_block(block_number).await
        }).map_err(DetectorError::RpcError)?;
        
        let hash = block
            .and_then(|b| b.hash)
            .unwrap_or_default();
        
        Ok(B256::from_slice(hash.as_bytes()))
    }
}
impl DatabaseCommit for EthersDB {
    /// Commit state changes
    fn commit(&mut self, changes: revm::primitives::HashMap<RevmAddress, revm::primitives::Account>) {
        // Store length before consuming the hashmap
        let num_changes = changes.len();

        // For simulation purposes, we commit to our cache
        for (address, account) in changes {
            let account_info = AccountInfo {
                balance: account.info.balance,
                nonce: account.info.nonce,
                code_hash: account.info.code_hash,
                code: account.info.code,
            };
            
            self.accounts.insert(address, account_info);
            
            // Commit storage changes
            for (slot, value) in account.storage {
                self.storage.insert((address, slot), value.present_value);
            }
        }
        
        tracing::trace!("Committed {} account changes", num_changes);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ethers_db_creation() {
        let client = Arc::new(
            BlockchainClient::new("https://rpc.pulsechain.com")
                .await
                .expect("Failed to connect to PulseChain")
        );
        
        let db = EthersDB::new(client);
        assert!(db.is_ok());
    }
    
    #[tokio::test]
    async fn test_fetch_wpls_account() {
        let client = Arc::new(
            BlockchainClient::new("https://rpc.pulsechain.com")
                .await
                .expect("Failed to connect to PulseChain")
        );
        
        let mut db = EthersDB::new(client).expect("Failed to create DB");
        
        // WPLS contract on PulseChain
        let wpls: Address = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27"
            .parse()
            .unwrap();
        let wpls_revm = EthersDB::to_revm_address(wpls);
        
        // Fetch account
        let account = db.basic(wpls_revm).expect("Failed to fetch account");
        
        assert!(account.is_some());
        let account = account.unwrap();
        assert!(account.code.is_some());
        println!("WPLS Balance: {}", account.balance);
        println!("WPLS has bytecode: {}", !account.code.unwrap().is_empty());
    }
}
