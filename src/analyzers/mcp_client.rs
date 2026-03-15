use crate::utils::{Result, DetectorError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::process::Stdio;
use std::time::Duration;

/// Analysis mode for Claude
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    Quick,   // $50, 5 min
    Hybrid,  // $100, 15 min (default)
    Deep,    // $200, 30 min
}

impl AnalysisMode {
    pub fn max_tokens(&self) -> u32 {
        match self {
            AnalysisMode::Quick => 50_000,
            AnalysisMode::Hybrid => 100_000,
            AnalysisMode::Deep => 200_000,
        }
    }

    pub fn timeout_secs(&self) -> u64 {
        match self {
            AnalysisMode::Quick => 300,   // 5 min
            AnalysisMode::Hybrid => 900,  // 15 min
            AnalysisMode::Deep => 1800,   // 30 min
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "quick" => Some(AnalysisMode::Quick),
            "hybrid" => Some(AnalysisMode::Hybrid),
            "deep" => Some(AnalysisMode::Deep),
            _ => None,
        }
    }
}

/// MCP JSON-RPC message types
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// Token usage tracking
#[derive(Debug, Clone)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}

impl TokenUsage {
    pub fn new() -> Self {
        Self {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
        }
    }

    pub fn add(&mut self, input: u32, output: u32) {
        self.input_tokens += input;
        self.output_tokens += output;
        self.total_tokens += input + output;
    }
}

/// MCP Tool definition from tools/list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP Client for communicating with the TypeScript MCP server
pub struct MCPClient {
    process: Option<Child>,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<BufReader<tokio::process::ChildStdout>>,
    initialized: bool,
    request_id: u64,
    mode: AnalysisMode,
    token_usage: TokenUsage,
}

impl MCPClient {
    /// Spawn the MCP server and complete handshake
    pub async fn new(mode: AnalysisMode) -> Result<Self> {
        let mcp_server_path = std::env::var("MCP_SERVER_PATH")
            .unwrap_or_else(|_| "./mcp-server/honeypot-tools.ts".to_string());

        tracing::info!("Spawning MCP server: {}", mcp_server_path);

        let mut child = Command::new("node")
            .arg("--no-warnings")
            .arg(&mcp_server_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| DetectorError::IoError(e))?;

        // Read stderr in background to prevent blocking
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 { break; }
                    tracing::debug!("MCP stderr: {}", line.trim());
                    line.clear();
                }
            });
        }

        // Get persistent handles
        let mut stdin = child.stdin.take()
            .ok_or_else(|| DetectorError::SimulationError("Failed to get MCP stdin".to_string()))?;
        
        let stdout = child.stdout.take()
            .ok_or_else(|| DetectorError::SimulationError("Failed to get MCP stdout".to_string()))?;
        
        let mut stdout = BufReader::new(stdout);

        // Give server a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 1: Send initialize request
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "honeypot-detector",
                    "version": "1.0.0"
                }
            }
        });

        let init_json = serde_json::to_string(&init_request)?;
        tracing::debug!("MCP initialize request: {}", init_json);
        
        stdin.write_all(init_json.as_bytes()).await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.write_all(b"\n").await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.flush().await
            .map_err(|e| DetectorError::IoError(e))?;

        // Step 2: Read initialize response with timeout
        let mut response_line = String::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(5),
            stdout.read_line(&mut response_line)
        ).await;

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                tracing::debug!("MCP initialize response: {}", response_line.trim());
                
                let response: JsonRpcResponse = serde_json::from_str(&response_line)
                    .map_err(|e| DetectorError::SimulationError(format!("Failed to parse initialize response: {}", e)))?;
                
                if let Some(error) = response.error {
                    return Err(DetectorError::SimulationError(
                        format!("MCP initialize error: {} (code: {})", error.message, error.code)
                    ));
                }

                // Validate server info
                if let Some(result) = response.result {
                    if result.get("protocolVersion").is_none() {
                        tracing::warn!("MCP server did not return protocolVersion");
                    }
                    tracing::info!("MCP server initialized: {:?}", result.get("serverInfo"));
                }
            },
            Ok(Ok(_)) => {
                return Err(DetectorError::SimulationError("MCP server closed connection during handshake".to_string()));
            },
            Ok(Err(e)) => {
                return Err(DetectorError::IoError(e));
            },
            Err(_) => {
                return Err(DetectorError::SimulationError("MCP initialize timeout (5s)".to_string()));
            }
        }

        // Step 3: Send initialized notification (no response expected)
        let initialized_notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let notif_json = serde_json::to_string(&initialized_notification)?;
        tracing::debug!("MCP initialized notification: {}", notif_json);
        
        stdin.write_all(notif_json.as_bytes()).await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.write_all(b"\n").await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.flush().await
            .map_err(|e| DetectorError::IoError(e))?;

        tracing::info!("MCP handshake completed successfully");

        Ok(Self {
            process: Some(child),
            stdin: Some(stdin),
            stdout: Some(stdout),
            initialized: true,
            request_id: 2, // Used 1 for initialize
            mode,
            token_usage: TokenUsage::new(),
        })
    }

    /// Get the next request ID
    fn next_id(&mut self) -> u64 {
        let current = self.request_id;
        self.request_id += 1;
        current
    }

    /// Send a JSON-RPC request and receive response (async with persistent streams)
    async fn call_tool(&mut self, tool_name: &str, params: Value) -> Result<Value> {
        if !self.initialized {
            return Err(DetectorError::SimulationError("MCP client not initialized".to_string()));
        }

        let id = self.next_id();

        let stdin = self.stdin.as_mut()
            .ok_or_else(|| DetectorError::SimulationError("MCP stdin not available".to_string()))?;
        
        let stdout = self.stdout.as_mut()
            .ok_or_else(|| DetectorError::SimulationError("MCP stdout not available".to_string()))?;
        
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id,
            method: "tools/call".to_string(),
            params: json!({
                "name": tool_name,
                "arguments": params
            }),
        };

        let request_json = serde_json::to_string(&request)?;
        tracing::debug!("MCP request: {}", request_json);

        // Send request
        stdin.write_all(request_json.as_bytes()).await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.write_all(b"\n").await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.flush().await
            .map_err(|e| DetectorError::IoError(e))?;

        // Read response with timeout
        let mut response_line = String::new();
        let read_result = tokio::time::timeout(
            Duration::from_secs(30),
            stdout.read_line(&mut response_line)
        ).await;

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                tracing::debug!("MCP response: {}", response_line.trim());
                
                let response: JsonRpcResponse = serde_json::from_str(&response_line)
                    .map_err(|e| DetectorError::SimulationError(format!("Failed to parse MCP response: {}", e)))?;

                if let Some(error) = response.error {
                    return Err(DetectorError::SimulationError(format!(
                        "MCP error: {} (code: {})", error.message, error.code
                    )));
                }

                response.result
                    .ok_or_else(|| DetectorError::SimulationError("No result in MCP response".to_string()))
            },
            Ok(Ok(_)) => {
                Err(DetectorError::SimulationError("MCP server closed connection".to_string()))
            },
            Ok(Err(e)) => {
                Err(DetectorError::IoError(e))
            },
            Err(_) => {
                Err(DetectorError::SimulationError("MCP tool call timeout (30s)".to_string()))
            }
        }
    }

    /// Discover available tools (tools/list)
    pub async fn discover_tools(&mut self) -> Result<Vec<MCPTool>> {
        if !self.initialized {
            return Err(DetectorError::SimulationError("MCP client not initialized".to_string()));
        }

        let id = self.next_id();

        let stdin = self.stdin.as_mut()
            .ok_or_else(|| DetectorError::SimulationError("MCP stdin not available".to_string()))?;
        
        let stdout = self.stdout.as_mut()
            .ok_or_else(|| DetectorError::SimulationError("MCP stdout not available".to_string()))?;
        
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list"
        });

        let request_json = serde_json::to_string(&request)?;
        tracing::debug!("MCP tools/list request: {}", request_json);

        stdin.write_all(request_json.as_bytes()).await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.write_all(b"\n").await
            .map_err(|e| DetectorError::IoError(e))?;
        stdin.flush().await
            .map_err(|e| DetectorError::IoError(e))?;

        let mut response_line = String::new();
        stdout.read_line(&mut response_line).await
            .map_err(|e| DetectorError::IoError(e))?;

        tracing::debug!("MCP tools/list response: {}", response_line.trim());

        let response: JsonRpcResponse = serde_json::from_str(&response_line)
            .map_err(|e| DetectorError::SimulationError(format!("Failed to parse tools/list response: {}", e)))?;

        if let Some(error) = response.error {
            return Err(DetectorError::SimulationError(format!(
                "MCP tools/list error: {} (code: {})", error.message, error.code
            )));
        }

        let result = response.result
            .ok_or_else(|| DetectorError::SimulationError("No result in tools/list response".to_string()))?;

        let tools: Vec<MCPTool> = serde_json::from_value(result["tools"].clone())
            .map_err(|e| DetectorError::SimulationError(format!("Failed to parse tools array: {}", e)))?;

        Ok(tools)
    }

    /// Get contract info (bytecode, size, chain)
    pub async fn get_contract_info(&mut self, address: &str, rpc_url: &str) -> Result<Value> {
        self.call_tool("get_contract_info", json!({
            "address": address,
            "rpcUrl": rpc_url
        })).await
    }

    /// Get verified source code from block explorer
    pub async fn get_source_code(&mut self, address: &str, chain_id: u64, api_key: Option<&str>) -> Result<Value> {
        let mut params = json!({
            "address": address,
            "chainId": chain_id
        });
        
        if let Some(key) = api_key {
            params["apiKey"] = json!(key);
        }

        self.call_tool("get_source_code", params).await
    }

    /// Analyze bytecode patterns
    pub async fn analyze_bytecode_patterns(&mut self, bytecode: &str, address: &str) -> Result<Value> {
        self.call_tool("analyze_bytecode_patterns", json!({
            "bytecode": bytecode,
            "address": address
        })).await
    }

    /// Simulate a transfer
    pub async fn simulate_transfer(&mut self, contract: &str, from: &str, to: &str, amount: &str, rpc_url: &str) -> Result<Value> {
        self.call_tool("simulate_transfer", json!({
            "contract": contract,
            "from": from,
            "to": to,
            "amount": amount,
            "rpcUrl": rpc_url
        })).await
    }

    /// Test approved holder sell
    pub async fn test_approved_holder_sell(&mut self, contract: &str, rpc_url: &str) -> Result<Value> {
        self.call_tool("test_approved_holder_sell", json!({
            "contract": contract,
            "rpcUrl": rpc_url
        })).await
    }

    /// Get current token usage
    pub fn token_usage(&self) -> TokenUsage {
        self.token_usage.clone()
    }

    /// Check if token budget is exceeded
    pub fn is_budget_exceeded(&self) -> bool {
        self.token_usage.total_tokens >= self.mode.max_tokens()
    }

    /// Update token usage (called after Claude API calls)
    pub fn update_tokens(&mut self, input: u32, output: u32) {
        self.token_usage.add(input, output);
    }

    /// Get analysis mode
    pub fn mode(&self) -> AnalysisMode {
        self.mode
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Drop for MCPClient {
    fn drop(&mut self) {
        // Kill the MCP server process when client is dropped
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
            tracing::debug!("MCP server process termination initiated");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_mode() {
        assert_eq!(AnalysisMode::Quick.max_tokens(), 50_000);
        assert_eq!(AnalysisMode::Hybrid.max_tokens(), 100_000);
        assert_eq!(AnalysisMode::Deep.max_tokens(), 200_000);

        assert_eq!(AnalysisMode::from_str("quick"), Some(AnalysisMode::Quick));
        assert_eq!(AnalysisMode::from_str("HYBRID"), Some(AnalysisMode::Hybrid));
        assert_eq!(AnalysisMode::from_str("deep"), Some(AnalysisMode::Deep));
        assert_eq!(AnalysisMode::from_str("invalid"), None);
    }

    #[test]
    fn test_token_usage() {
        let mut usage = TokenUsage::new();
        usage.add(100, 50);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.total_tokens, 150);

        usage.add(200, 100);
        assert_eq!(usage.input_tokens, 300);
        assert_eq!(usage.output_tokens, 150);
        assert_eq!(usage.total_tokens, 450);
    }
}
