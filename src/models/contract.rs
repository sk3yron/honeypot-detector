use ethers::types::Address;

#[derive(Debug, Clone)]
pub struct ContractTarget {
    pub address: Address,
    pub bytecode: Option<Vec<u8>>,
    pub is_proxy: Option<bool>,
    pub implementation: Option<Address>,
}

impl ContractTarget {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            bytecode: None,
            is_proxy: None,
            implementation: None,
        }
    }
    
    pub fn with_bytecode(mut self, bytecode: Vec<u8>) -> Self {
        self.bytecode = Some(bytecode);
        self
    }
}