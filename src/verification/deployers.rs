//! Known scammer deployer blacklist for PulseChain

use ethers::types::Address;
use std::str::FromStr;
use once_cell::sync::Lazy;
use std::collections::HashSet;

/// List of known scammer deployer addresses on PulseChain
/// These addresses have been verified to deploy honeypots/rugpulls
pub const KNOWN_SCAMMERS: &[&str] = &[
    // Add verified scammer addresses here as they are identified
    // Example: "0xSCAMMERADDRESS1...",
];

/// Parsed scammer addresses (lazy-loaded)
static SCAMMER_SET: Lazy<HashSet<Address>> = Lazy::new(|| {
    KNOWN_SCAMMERS
        .iter()
        .filter_map(|addr| Address::from_str(addr).ok())
        .collect()
});

/// Check if address is a known scammer
pub fn is_known_scammer(address: Address) -> bool {
    SCAMMER_SET.contains(&address)
}

/// Add a scammer address (for runtime updates)
/// Note: This is not persistent - consider adding database storage in production
pub fn add_scammer(_address: Address) {
    // TODO: Implement persistent storage (database, file, etc.)
    // For now, this is a no-op
    tracing::warn!("add_scammer() not implemented - use static list");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_no_false_positives() {
        // Random address should not be flagged as scammer
        let random = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        assert!(!is_known_scammer(random));
    }
}
