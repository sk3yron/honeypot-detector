//! Storage layout types and patterns

/// Known storage layout patterns for ERC20 tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageLayout {
    /// OpenZeppelin ERC20 layout
    /// - Slot 0: mapping(address => uint256) _balances
    /// - Slot 1: mapping(address => mapping(address => uint256)) _allowances  
    /// - Slot 2: uint256 _totalSupply
    OpenZeppelin,
    
    /// Solmate ERC20 layout
    /// - Slot 3: mapping(address => uint256) balanceOf
    /// - Different from OpenZeppelin
    Solmate,
    
    /// Custom layout with specific slot number
    Custom(u8),
    
    /// Could not determine layout
    Unknown,
}

/// Information about detected storage layout
#[derive(Debug, Clone)]
pub struct LayoutInfo {
    /// Detected layout type
    pub layout: StorageLayout,
    
    /// Slot number where balances mapping is stored
    pub balances_slot: u8,
    
    /// Whether the layout was verified by actual storage read
    pub verified: bool,
}

impl StorageLayout {
    /// Get the slot number for balances mapping
    pub fn balances_slot(&self) -> Option<u8> {
        match self {
            StorageLayout::OpenZeppelin => Some(0),
            StorageLayout::Solmate => Some(3),
            StorageLayout::Custom(slot) => Some(*slot),
            StorageLayout::Unknown => None,
        }
    }
    
    /// Get the slot number for allowances mapping
    pub fn allowances_slot(&self) -> Option<u8> {
        match self {
            StorageLayout::OpenZeppelin => Some(1),
            StorageLayout::Solmate => Some(4),
            StorageLayout::Custom(_) => None, // Unknown
            StorageLayout::Unknown => None,
        }
    }
    
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            StorageLayout::OpenZeppelin => "OpenZeppelin",
            StorageLayout::Solmate => "Solmate",
            StorageLayout::Custom(_) => "Custom",
            StorageLayout::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for StorageLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageLayout::OpenZeppelin => write!(f, "OpenZeppelin (slot 0)"),
            StorageLayout::Solmate => write!(f, "Solmate (slot 3)"),
            StorageLayout::Custom(slot) => write!(f, "Custom (slot {})", slot),
            StorageLayout::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_layout() {
        let oz = StorageLayout::OpenZeppelin;
        assert_eq!(oz.balances_slot(), Some(0));
        assert_eq!(oz.allowances_slot(), Some(1));
        assert_eq!(oz.name(), "OpenZeppelin");
        
        let solmate = StorageLayout::Solmate;
        assert_eq!(solmate.balances_slot(), Some(3));
        
        let custom = StorageLayout::Custom(5);
        assert_eq!(custom.balances_slot(), Some(5));
    }
}
