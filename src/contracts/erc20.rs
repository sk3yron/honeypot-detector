//! ERC20 token interface
//! Standard interface for inteacting with ERC20 tokens
use ethers::prelude::*;
// Generate contract bindings using abigen macro
abigen!(
    IERC20,
    r#"[
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
        function transfer(address to, uint256 amount) external returns (bool)
        function allowance(address owner, address spender) external view returns (uint256)
        function approve(address spender, uint256 amount) external returns (bool)
        function transferFrom(address from, address to, uint256 amount) external returns (bool)
        function decimals() external view returns (uint8)
        function name() external view returns (string)
        function symbol() external view returns (string)
        event Transfer(address indexed from, address indexed to, uint256 value)
        event Approval(address indexed owner, address indexed spender, uint256 value)
    ]"#,
);
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    fn test_erc20_interface() {
        // Test that the interface is generated correctly
        // This is a compile-time test - if it compiles, the interface is valid
        assert!(true);
    }
}
