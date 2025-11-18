//! PulseX Pair interface(UniswapV2Pair fork)
//! Used to query liquidity pool reserves
use ethers::prelude::*;
abigen!(
    IPulseXPair,
    r#"[
        function token0() external view returns (address)
        function token1() external view returns (address)
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
        function price0CumulativeLast() external view returns (uint256)
        function price1CumulativeLast() external view returns (uint256)
        function kLast() external view returns (uint256)
        event Sync(uint112 reserve0, uint112 reserve1)
        event Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to)
    ]"#,
);
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pulsex_pair_interface() {
        // Compile-time test for interface generation
        assert!(true);
    }
} 
