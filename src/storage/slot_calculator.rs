//! Solidity storage slot calculation utilities
//! 
//! In Solidity, mapping storage slots are calculated as:
//! slot = keccak256(abi.encode(key, mapping_slot))

use ethers::types::{Address, U256};
use sha3::{Digest, Keccak256};

/// Calculate storage slot for mapping(address => uint256)
/// 
/// Formula: keccak256(abi.encode(address, base_slot))
/// 
/// # Arguments
/// * `address` - The key (address) to look up in the mapping
/// * `base_slot` - The slot number where the mapping is declared
/// 
/// # Returns
/// The calculated storage slot as U256
pub fn calculate_mapping_slot(address: Address, base_slot: u8) -> U256 {
    // Create 64-byte buffer: [address (32 bytes) | slot (32 bytes)]
    let mut bytes = [0u8; 64];
    
    // First 32 bytes: left-pad address to 32 bytes
    // Address is 20 bytes, so pad 12 zeros on the left
    bytes[12..32].copy_from_slice(address.as_bytes());
    
    // Second 32 bytes: right-pad slot number to 32 bytes
    // Slot is u8, so it goes in the last byte
    bytes[63] = base_slot;
    
    // Hash with keccak256
    let hash = Keccak256::digest(&bytes);
    
    // Convert to U256
    U256::from_big_endian(&hash[..])
}

/// Calculate storage slot for nested mapping: mapping(address => mapping(address => uint256))
/// 
/// Formula: keccak256(abi.encode(inner_key, keccak256(abi.encode(outer_key, base_slot))))
/// 
/// Used for allowances: mapping(owner => mapping(spender => uint256))
pub fn calculate_nested_mapping_slot(
    outer_key: Address,
    inner_key: Address,
    base_slot: u8,
) -> U256 {
    // First, calculate the slot for the outer mapping
    let outer_slot = calculate_mapping_slot(outer_key, base_slot);
    
    // Convert outer_slot to bytes
    let mut outer_slot_bytes = [0u8; 32];
    outer_slot.to_big_endian(&mut outer_slot_bytes);
    
    // Now calculate inner mapping slot
    let mut bytes = [0u8; 64];
    bytes[12..32].copy_from_slice(inner_key.as_bytes());
    bytes[32..64].copy_from_slice(&outer_slot_bytes);
    
    let hash = Keccak256::digest(&bytes);
    U256::from_big_endian(&hash[..])
}

/// Generic keccak256 concatenation helper
pub fn keccak256_concat(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for chunk in data {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[test]
    fn test_calculate_mapping_slot() {
        // Test with known values
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let slot = calculate_mapping_slot(addr, 0);
        
        // The result should be deterministic
        assert!(slot > U256::zero());
        
        // Same input should give same output
        let slot2 = calculate_mapping_slot(addr, 0);
        assert_eq!(slot, slot2);
    }
    
    #[test]
    fn test_different_slots_different_results() {
        let addr = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let slot0 = calculate_mapping_slot(addr, 0);
        let slot1 = calculate_mapping_slot(addr, 1);
        
        assert_ne!(slot0, slot1);
    }
    
    #[test]
    fn test_nested_mapping_slot() {
        let owner = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let spender = Address::from_str("0x0000000000000000000000000000000000000002").unwrap();
        
        let slot = calculate_nested_mapping_slot(owner, spender, 1);
        assert!(slot > U256::zero());
    }
}
