//! PulseX Router interfae (UniswapV2Router02 fork)
//! Used for swap calculations and simulations
use ethers::prelude::*;
abigen!(
    IPulseXRouter,
    r#"[
        function factory() external pure returns (address)
        function WPLS() external pure returns (address)
        function addLiquidity(address tokenA, address tokenB, uint amountADesired, uint amountBDesired, uint amountAMin, uint amountBMin, address to, uint deadline) external returns (uint amountA, uint amountB, uint liquidity)
        function addLiquidityPLS(address token, uint amountTokenDesired, uint amountTokenMin, uint amountPLSMin, address to, uint deadline) external payable returns (uint amountToken, uint amountPLS, uint liquidity)
        function removeLiquidity(address tokenA, address tokenB, uint liquidity, uint amountAMin, uint amountBMin, address to, uint deadline) external returns (uint amountA, uint amountB)
        function removeLiquidityPLS(address token, uint liquidity, uint amountTokenMin, uint amountPLSMin, address to, uint deadline) external returns (uint amountToken, uint amountPLS)
        function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)
        function swapTokensForExactTokens(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)
        function swapExactPLSForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts)
        function swapTokensForExactPLS(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)
        function swapExactTokensForPLS(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)
        function swapPLSForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts)
        function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB)
        function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut)
        function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn)
        function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts)
        function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts)
    ]"#,
);
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pulsex_router_interface() {
        // Compile-time test for interface generation
        assert!(true);
    }
}
