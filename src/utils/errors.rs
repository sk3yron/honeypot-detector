use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectorError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    #[error("RPC error: {0}")]
    RpcError(#[from] ethers::providers::ProviderError),
    
    #[error("Contract not found at address {0}")]
    ContractNotFound(String),
    
    #[error("Bytecode analysis failed: {0}")]
    AnalysisError(String),
    
    #[error("ML model error: {0}")]
    MLError(String),
    
    #[error("Simulation failed: {0}")]
    SimulationError(String),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[cfg(feature = "ml-inference")]
    #[error("ONNX error: {0}")]
    OnnxError(#[from] ort::OrtError), 
    
    #[cfg(feature = "ml-inference")]
    #[error("Array shape error: {0}")]
    ShapeError(#[from] ndarray::ShapeError),
}

pub type Result<T> = std::result::Result<T, DetectorError>;