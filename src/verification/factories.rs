//! Trusted factory whitelist for PulseChain

use ethers::types::Address;
use std::str::FromStr;
use once_cell::sync::Lazy;
use std::collections::HashSet;

/// List of trusted token factories on PulseChain
/// These factories are verified to create legitimate tokens
pub const TRUSTED_FACTORIES: &[&str] = &[
    "0xcf6402cdEdfF50Fe334471D0fDD33014E40e828c", // Pump.Tires - verified token launcher
    // Add more verified factories here as they are identified
];

/// Parsed trusted factory addresses (lazy-loaded)
static TRUSTED_SET: Lazy<HashSet<Address>> = Lazy::new(|| {
    TRUSTED_FACTORIES
        .iter()
        .filter_map(|addr| Address::from_str(addr).ok())
        .collect()
});

/// Check if address is a trusted factory
pub fn is_trusted_factory(address: Address) -> bool {
    TRUSTED_SET.contains(&address)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pump_tires_is_trusted() {
        let pump_tires = Address::from_str("0xcf6402cdEdfF50Fe334471D0fDD33014E40e828c").unwrap();
        assert!(is_trusted_factory(pump_tires));
    }
    
    #[test]
    fn test_random_address_not_trusted() {
        let random = Address::from_str("0x0000000000000000000000000000000000000001").unwrap();
        assert!(!is_trusted_factory(random));
    }
}
