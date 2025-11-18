//! PulseX contract interaces for interacting with DEX components
//! 
//! PulseX is a UniswapV2 fork on PulseChain. These interfaces allow us to:
//! - Query pair reserves for swap simulation
//! - Interact with the router for swap calculations
//! - Verify token factories
pub mod erc20;
pub mod pulsex_pair;
pub mod pulsex_router;
pub mod pulsex_factory;
pub use erc20::IERC20;
pub use pulsex_pair::IPulseXPair;
pub use pulsex_router::IPulseXRouter;
pub use pulsex_factory::IPulseXFactory;
use ethers::types::Address;
/// PulseX contract addresses on PulseChain (Chain ID: 369)
pub mod addresses {
    use super::Address;
    use std::str::FromStr;
    
    /// PulseX Factory address
    pub const PULSEX_FACTORY: &str = "0x29eA7545DEf87022BAdc76323F373EA1e707C523";
    
    /// PulseX Router V1 address (commonly used on PulseX.com)
    pub const PULSEX_ROUTER_V1: &str = "0xda9aba4eacf54e0273f56dffee6b8f1e20b23bba";
    
    /// PulseX Router V2 address
    pub const PULSEX_ROUTER_V2: &str = "0x165C3410fC91EF562C50559f7d2289fEbed552d9";
    
    /// Piteas Router address (aggregator router commonly used for concurrent swaps)
    pub const PITEAS_ROUTER: &str = "0x6BF228eb7F8ad948d37deD07E595EfddfaAF88A6";
    
    /// Default router (V1)
    pub const PULSEX_ROUTER: &str = PULSEX_ROUTER_V1;
    
    /// Wrapped PLS (WPLS) address
    pub const WPLS: &str = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27";
    
    /// Get all supported router addresses (PulseX V1, V2, and Piteas)
    pub fn all_routers() -> Vec<&'static str> {
        vec![PULSEX_ROUTER_V1, PULSEX_ROUTER_V2, PITEAS_ROUTER]
    }
    
    /// Parse PULSEX_FACTORY as Address
    pub fn pulsex_factory() -> Address {
        Address::from_str(PULSEX_FACTORY).expect("Invalid PULSEX_FACTORY address")
    }
    
    /// Parse PULSEX_ROUTER as Address
    pub fn pulsex_router() -> Address {
        Address::from_str(PULSEX_ROUTER).expect("Invalid PULSEX_ROUTER address")
    }
    
    /// Parse WPLS as Address
    pub fn wpls() -> Address {
        Address::from_str(WPLS).expect("Invalid WPLS address")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pulsex_addresses() {
        let factory = addresses::pulsex_factory();
        let router = addresses::pulsex_router();
        let wpls = addresses::wpls();
        
        assert_eq!(format!("{:?}", factory).to_lowercase(), "0x29ea7545def87022badc76323f373ea1e707c523");
        assert_eq!(format!("{:?}", router).to_lowercase(), "0xda9aba4eacf54e0273f56dffee6b8f1e20b23bba");
        assert_eq!(format!("{:?}", wpls).to_lowercase(), "0xa1077a294dde1b09bb078844df40758a5d0f9a27");
    }
}
