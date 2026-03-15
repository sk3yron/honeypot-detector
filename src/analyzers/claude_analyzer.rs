use async_trait::async_trait;
use crate::core::traits::Analyzer;
use crate::models::{ContractTarget, AnalysisResult, Finding, Severity, Category};
use crate::utils::{Result, DetectorError};
use crate::analyzers::mcp_client::{MCPClient, AnalysisMode};
use crate::blockchain::BlockchainClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::path::Path;

/// Type of Claude analysis to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeAnalysisType {
    /// Full contract analysis with MCP tools
    Full,
    /// Review static analyzer findings only (faster, cheaper)
    StaticReview,
}

/// Claude API tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaudeTool {
    name: String,
    description: String,
    input_schema: Value,
}

/// Claude API message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

/// Claude API message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    role: String,
    content: Vec<ContentBlock>,
}

impl Message {
    fn user(text: String) -> Self {
        Self {
            role: "user".to_string(),
            content: vec![ContentBlock::Text { text }],
        }
    }

    fn assistant(content: Vec<ContentBlock>) -> Self {
        Self {
            role: "assistant".to_string(),
            content,
        }
    }

    fn tool_result(tool_use_id: String, result: String) -> Self {
        Self {
            role: "user".to_string(),
            content: vec![ContentBlock::ToolResult {
                tool_use_id,
                content: result,
            }],
        }
    }
}

/// Claude API response
#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    id: String,
    #[serde(rename = "type")]
    response_type: String,
    role: String,
    content: Vec<ContentBlock>,
    stop_reason: String,
    usage: Option<Value>,
}

/// Claude's analysis response structure
#[derive(Debug, Deserialize, Serialize)]
struct ClaudeAnalysis {
    risk_score: u8,
    is_honeypot: bool,
    confidence: f64,
    findings: Vec<ClaudeFinding>,
    reasoning: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClaudeFinding {
    severity: String,
    category: String,
    message: String,
    evidence: Option<Value>,
}

/// Claude AI analyzer using MCP
pub struct ClaudeAnalyzer {
    mode: AnalysisMode,
    analysis_type: ClaudeAnalysisType,
    blockchain_client: Arc<BlockchainClient>,
    rpc_url: String,
    system_prompt: String,
    mode_prompt: String,
    cache_db: Arc<sled::Db>,
}

impl ClaudeAnalyzer {
    /// Create a new Claude analyzer
    pub fn new(mode: AnalysisMode, blockchain_client: Arc<BlockchainClient>, rpc_url: String) -> Result<Self> {
        // Load prompts from files
        let prompts_dir = std::env::var("PROMPTS_DIR")
            .unwrap_or_else(|_| "./prompts".to_string());
        
        let system_prompt = Self::load_prompt(&prompts_dir, "system_prompt.md")?;
        let mode_prompt = Self::load_mode_prompt(&prompts_dir, mode)?;

        // Open cache database
        let cache_path = std::env::var("CACHE_DIR")
            .unwrap_or_else(|_| "./cache".to_string());
        let cache_db = sled::open(format!("{}/claude_cache", cache_path))
            .map_err(|e| DetectorError::CacheError(format!("Failed to open cache: {}", e)))?;

        // Determine analysis type from env var or default to tool-use
        let analysis_type = std::env::var("CLAUDE_ANALYSIS_TYPE")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "full" => Some(ClaudeAnalysisType::Full),
                "static_review" => Some(ClaudeAnalysisType::StaticReview),
                _ => None,
            })
            .unwrap_or(ClaudeAnalysisType::Full);

        tracing::info!("Claude analyzer initialized with analysis type: {:?}", analysis_type);

        Ok(Self {
            mode,
            analysis_type,
            blockchain_client,
            rpc_url,
            system_prompt,
            mode_prompt,
            cache_db: Arc::new(cache_db),
        })
    }

    /// Load a prompt file
    fn load_prompt(dir: &str, filename: &str) -> Result<String> {
        let path = Path::new(dir).join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| DetectorError::IoError(e))
    }

    /// Load mode-specific prompt
    fn load_mode_prompt(dir: &str, mode: AnalysisMode) -> Result<String> {
        let filename = match mode {
            AnalysisMode::Quick => "quick_mode.md",
            AnalysisMode::Hybrid => "hybrid_mode.md",
            AnalysisMode::Deep => "deep_mode.md",
        };
        Self::load_prompt(dir, filename)
    }

    /// Check cache for previous analysis
    fn get_cached_result(&self, address: &str) -> Option<AnalysisResult> {
        let cache_key = format!("{}:{:?}", address, self.mode);
        
        if let Ok(Some(cached)) = self.cache_db.get(cache_key.as_bytes()) {
            if let Ok(cached_data) = bincode::deserialize::<CachedAnalysis>(&cached) {
                // Check if cache is still valid
                let now = chrono::Utc::now().timestamp();
                let age_hours = (now - cached_data.timestamp) / 3600;
                
                // Cache for 24h if honeypot, 12h if safe
                let max_age = if cached_data.result.risk_score >= 60 { 24 } else { 12 };
                
                if age_hours < max_age {
                    tracing::debug!("Using cached Claude analysis (age: {}h)", age_hours);
                    return Some(cached_data.result);
                }
            }
        }
        None
    }

    /// Save result to cache
    fn cache_result(&self, address: &str, result: &AnalysisResult) {
        let cache_key = format!("{}:{:?}", address, self.mode);
        let cached = CachedAnalysis {
            result: result.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        };
        
        if let Ok(serialized) = bincode::serialize(&cached) {
            let _ = self.cache_db.insert(cache_key.as_bytes(), serialized);
        }
    }

    /// Review static analyzer findings with Claude AI
    pub async fn review_static_findings(
        &self,
        static_result: &AnalysisResult,
        address: &str,
        chain: &str,
    ) -> Result<AnalysisResult> {
        tracing::info!("Starting Claude static review for {}", address);

        // Load the static review prompt template
        let prompts_dir = std::env::var("PROMPTS_DIR")
            .unwrap_or_else(|_| "./prompts".to_string());
        let template = Self::load_prompt(&prompts_dir, "static_analysis_review.md")?;

        // Build the prompt with static findings
        let prompt = self.build_static_review_prompt(&template, static_result, address, chain);

        // Call Claude API (simplified, no MCP tools needed)
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| DetectorError::ConfigError("ANTHROPIC_API_KEY not set".to_string()))?;

        tracing::debug!("Calling Claude API for static review...");

        let client = reqwest::Client::new();
        let request_body = serde_json::json!({
            "model": "claude-opus-4-20250514",
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.5
        });

        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Claude API request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error body".to_string());
            
            tracing::warn!("Claude API error: {} - {}", status, error_body);
            
            // Graceful degradation - return the original static result
            return Ok(static_result.clone());
        }

        let response_json: Value = response
            .json()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Failed to parse Claude API response: {}", e)))?;

        // Extract text content
        let content = response_json
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| DetectorError::NetworkError("No text content in Claude response".to_string()))?;

        tracing::debug!("Claude static review response:\n{}", content);

        // Parse Claude's JSON response
        let json_content = if content.contains("```json") {
            content
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .map(|s| s.trim())
                .unwrap_or(content)
        } else if content.trim().starts_with('{') {
            content.trim()
        } else {
            // Try to find JSON in the response
            if let Some(start) = content.find('{') {
                if let Some(end) = content.rfind('}') {
                    &content[start..=end]
                } else {
                    content
                }
            } else {
                content
            }
        };

        let analysis: ClaudeAnalysis = serde_json::from_str(json_content)
            .map_err(|e| {
                tracing::error!("Failed to parse Claude's static review JSON: {}", e);
                DetectorError::JsonError(e)
            })?;

        // Convert to AnalysisResult
        let mut result = AnalysisResult::new(analysis.risk_score);
        
        for cf in analysis.findings {
            result.add_finding(self.convert_finding(cf));
        }

        result.metadata.insert(
            "claude_static_review".to_string(),
            serde_json::json!(true)
        );
        result.metadata.insert(
            "claude_reasoning".to_string(),
            serde_json::json!(analysis.reasoning)
        );
        result.metadata.insert(
            "claude_confidence".to_string(),
            serde_json::json!(analysis.confidence)
        );

        tracing::info!("Claude static review complete: risk_score={}", analysis.risk_score);

        Ok(result)
    }

    /// Build the static review prompt from template
    fn build_static_review_prompt(
        &self,
        template: &str,
        static_result: &AnalysisResult,
        address: &str,
        chain: &str,
    ) -> String {
        // Build findings section
        let findings_section = if static_result.findings.is_empty() {
            "No findings reported by static analyzer.".to_string()
        } else {
            let mut section = String::new();
            for (i, finding) in static_result.findings.iter().enumerate() {
                section.push_str(&format!(
                    "{}. **{:?}** - {:?}: {}\n",
                    i + 1,
                    finding.severity,
                    finding.category,
                    finding.message
                ));
                if let Some(evidence) = &finding.evidence {
                    section.push_str(&format!("   Evidence: {}\n", 
                        serde_json::to_string_pretty(evidence).unwrap_or_default()));
                }
            }
            section
        };

        // Build patterns section from metadata
        let patterns_section = if let Some(patterns) = static_result.metadata.get("patterns") {
            serde_json::to_string_pretty(patterns).unwrap_or("None detected".to_string())
        } else {
            "None detected".to_string()
        };

        let bytecode_size = static_result.metadata
            .get("bytecode_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Replace template placeholders
        template
            .replace("{{address}}", address)
            .replace("{{chain}}", chain)
            .replace("{{bytecode_size}}", &bytecode_size.to_string())
            .replace("{{findings_section}}", &findings_section)
            .replace("{{patterns_section}}", &patterns_section)
    }

    /// Convert MCP tools to Claude API tool format
    async fn get_claude_tools(&self, mcp_client: &mut MCPClient) -> Result<Vec<ClaudeTool>> {
        tracing::debug!("Discovering MCP tools...");
        
        let mcp_tools = mcp_client.discover_tools().await?;
        
        tracing::info!("Discovered {} MCP tools", mcp_tools.len());
        
        // Convert to Claude format
        let claude_tools: Vec<ClaudeTool> = mcp_tools
            .into_iter()
            .map(|tool| ClaudeTool {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
            })
            .collect();
        
        Ok(claude_tools)
    }

    /// Execute an MCP tool call
    async fn execute_mcp_tool(
        &self,
        mcp_client: &mut MCPClient,
        tool_name: &str,
        tool_input: &Value,
    ) -> Result<String> {
        tracing::debug!("Executing MCP tool: {} with input: {:?}", tool_name, tool_input);
        
        let result = match tool_name {
            "get_contract_info" => {
                let address = tool_input["address"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing address parameter".to_string()))?;
                let rpc_url = tool_input["rpcUrl"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing rpcUrl parameter".to_string()))?;
                
                mcp_client.get_contract_info(address, rpc_url).await?
            },
            "get_source_code" => {
                let address = tool_input["address"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing address parameter".to_string()))?;
                let chain_id = tool_input["chainId"].as_u64()
                    .ok_or_else(|| DetectorError::SimulationError("Missing chainId parameter".to_string()))?;
                let api_key = tool_input["apiKey"].as_str();
                
                mcp_client.get_source_code(address, chain_id, api_key).await?
            },
            "analyze_bytecode_patterns" => {
                let bytecode = tool_input["bytecode"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing bytecode parameter".to_string()))?;
                let address = tool_input["address"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing address parameter".to_string()))?;
                
                mcp_client.analyze_bytecode_patterns(bytecode, address).await?
            },
            "simulate_transfer" => {
                let contract = tool_input["contract"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing contract parameter".to_string()))?;
                let from = tool_input["from"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing from parameter".to_string()))?;
                let to = tool_input["to"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing to parameter".to_string()))?;
                let amount = tool_input["amount"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing amount parameter".to_string()))?;
                let rpc_url = tool_input["rpcUrl"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing rpcUrl parameter".to_string()))?;
                
                mcp_client.simulate_transfer(contract, from, to, amount, rpc_url).await?
            },
            "test_approved_holder_sell" => {
                let contract = tool_input["contract"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing contract parameter".to_string()))?;
                let rpc_url = tool_input["rpcUrl"].as_str()
                    .ok_or_else(|| DetectorError::SimulationError("Missing rpcUrl parameter".to_string()))?;
                
                mcp_client.test_approved_holder_sell(contract, rpc_url).await?
            },
            _ => {
                return Err(DetectorError::SimulationError(format!("Unknown tool: {}", tool_name)));
            }
        };
        
        // Convert result to string
        let result_str = serde_json::to_string_pretty(&result)
            .unwrap_or_else(|_| format!("{:?}", result));
        
        tracing::debug!("MCP tool result: {}", result_str);
        
        Ok(result_str)
    }

    /// Run Claude analysis with autonomous tool use
    async fn run_claude_analysis_with_tools(&self, target: &ContractTarget) -> Result<ClaudeAnalysis> {
        let address_str = format!("{:?}", target.address);
        let chain_id = self.blockchain_client.chain_id();

        tracing::info!("Starting Claude analysis with tool-use in {:?} mode", self.mode);

        // Create MCP client for tool access
        let mut mcp_client = MCPClient::new(self.mode).await?;

        // Get available tools
        let tools = self.get_claude_tools(&mut mcp_client).await?;

        // Build initial prompt
        let initial_prompt = format!(
            "{}\n\n{}\n\n# Contract Analysis Request\n\n\
            **Address:** {}\n\
            **Chain ID:** {}\n\
            **RPC URL:** {}\n\n\
            Analyze this contract for honeypot characteristics. You have access to tools \
            to gather information about the contract. Use them to conduct a thorough analysis.\n\n\
            Provide your final analysis in the following JSON format:\n\
            ```json\n\
            {{\n  \
              \"risk_score\": <0-100>,\n  \
              \"is_honeypot\": <true/false>,\n  \
              \"confidence\": <0.0-1.0>,\n  \
              \"findings\": [\n    \
                {{\n      \
                  \"severity\": \"<critical|high|medium|low|info>\",\n      \
                  \"category\": \"<BytecodePattern|Honeypot|Ownership|etc>\",\n      \
                  \"message\": \"<description>\"\n    \
                }}\n  \
              ],\n  \
              \"reasoning\": \"<your analysis>\"\n\
            }}\n\
            ```",
            self.system_prompt,
            self.mode_prompt,
            address_str,
            chain_id,
            self.rpc_url
        );

        let mut messages = vec![Message::user(initial_prompt)];
        let mut tool_use_count = 0;
        const MAX_TOOL_USES: usize = 10;

        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| DetectorError::ConfigError("ANTHROPIC_API_KEY not set".to_string()))?;

        let client = reqwest::Client::new();

        // Tool-use loop
        loop {
            tracing::debug!("Claude API call (tool use count: {})", tool_use_count);

            // Prepare request body
            let request_body = serde_json::json!({
                "model": "claude-opus-4-20250514",
                "max_tokens": 4096,
                "messages": messages,
                "tools": tools,
                "temperature": 0.7
            });

            // Call Claude API
            let response = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&request_body)
                .send()
                .await
                .map_err(|e| DetectorError::NetworkError(format!("Claude API request failed: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error body".to_string());
                return Err(DetectorError::NetworkError(format!(
                    "Claude API returned error {}: {}",
                    status,
                    error_body
                )));
            }

            let claude_response: ClaudeResponse = response
                .json()
                .await
                .map_err(|e| DetectorError::NetworkError(format!("Failed to parse Claude API response: {}", e)))?;

            // Update token usage
            if let Some(usage) = claude_response.usage {
                let input_tokens = usage["input_tokens"].as_u64().unwrap_or(0) as u32;
                let output_tokens = usage["output_tokens"].as_u64().unwrap_or(0) as u32;
                mcp_client.update_tokens(input_tokens, output_tokens);
            }

            tracing::debug!("Claude stop_reason: {}", claude_response.stop_reason);

            match claude_response.stop_reason.as_str() {
                "end_turn" => {
                    // Claude has finished - extract final answer
                    for content in &claude_response.content {
                        if let ContentBlock::Text { text } = content {
                            tracing::debug!("Claude's final response:\n{}", text);
                            
                            // Parse JSON from response
                            let json_content = if text.contains("```json") {
                                text.split("```json")
                                    .nth(1)
                                    .and_then(|s| s.split("```").next())
                                    .map(|s| s.trim())
                                    .unwrap_or(text)
                            } else if text.trim().starts_with('{') {
                                text.trim()
                            } else {
                                if let Some(start) = text.find('{') {
                                    if let Some(end) = text.rfind('}') {
                                        &text[start..=end]
                                    } else {
                                        text
                                    }
                                } else {
                                    text
                                }
                            };

                            let analysis: ClaudeAnalysis = serde_json::from_str(json_content)
                                .map_err(|e| DetectorError::JsonError(e))?;

                            return Ok(analysis);
                        }
                    }
                    
                    return Err(DetectorError::NetworkError("No text content in Claude's final response".to_string()));
                },
                "tool_use" => {
                    // Claude wants to use tools
                    tool_use_count += 1;
                    
                    if tool_use_count > MAX_TOOL_USES {
                        return Err(DetectorError::SimulationError(
                            format!("Maximum tool uses ({}) exceeded", MAX_TOOL_USES)
                        ));
                    }

                    // Add Claude's response to message history
                    messages.push(Message::assistant(claude_response.content.clone()));

                    // Execute each tool use
                    for content in &claude_response.content {
                        if let ContentBlock::ToolUse { id, name, input } = content {
                            tracing::info!("Claude is using tool: {} (id: {})", name, id);
                            
                            // Execute the tool via MCP
                            let tool_result = self.execute_mcp_tool(&mut mcp_client, name, input).await?;
                            
                            // Add tool result to messages
                            messages.push(Message::tool_result(id.clone(), tool_result));
                        }
                    }

                    // Continue loop - call Claude again with tool results
                    continue;
                },
                _ => {
                    return Err(DetectorError::NetworkError(
                        format!("Unexpected stop_reason: {}", claude_response.stop_reason)
                    ));
                }
            }
        }
    }

    /// Run Claude analysis via API with MCP tools (legacy method - simple data gathering)
    async fn run_claude_analysis(&self, target: &ContractTarget) -> Result<ClaudeAnalysis> {
        let address_str = format!("{:?}", target.address);
        let chain_id = self.blockchain_client.chain_id();

        tracing::info!("Starting Claude analysis in {:?} mode", self.mode);

        // Create MCP client for tool access (now async with handshake)
        let mut mcp_client = MCPClient::new(self.mode).await?;

        // Gather data using MCP tools
        tracing::debug!("Gathering contract data via MCP tools...");
        
        // Step 1: Get contract info via MCP
        let contract_info = match mcp_client.get_contract_info(&address_str, &self.rpc_url).await {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("Failed to get contract info via MCP: {}", e);
                // Fallback to basic info
                serde_json::json!({
                    "address": address_str,
                    "bytecode_size": target.bytecode.as_ref().map(|b| b.len()).unwrap_or(0),
                    "chain_id": chain_id,
                })
            }
        };

        // Step 2: Try to get source code
        let source_code = mcp_client.get_source_code(&address_str, chain_id, None).await.ok();

        // Step 3: Analyze bytecode patterns if we have bytecode
        let patterns = if let Some(ref bytecode) = target.bytecode {
            let bytecode_hex = hex::encode(bytecode);
            mcp_client.analyze_bytecode_patterns(&bytecode_hex, &address_str).await.ok()
        } else {
            None
        };

        // Build the analysis prompt with MCP-gathered data
        let analysis_prompt = self.build_analysis_prompt(
            &address_str,
            &contract_info,
            source_code.as_ref(),
            patterns.as_ref(),
            None,  // holder_test - optional
        );

        tracing::debug!("Calling Claude API with MCP-gathered data...");
        let claude_response = self.call_claude_api(&mut mcp_client, &analysis_prompt).await?;

        // Parse Claude's response
        let analysis: ClaudeAnalysis = serde_json::from_value(claude_response)
            .map_err(|e| DetectorError::JsonError(e))?;

        // Log token usage
        let usage = mcp_client.token_usage();
        tracing::info!(
            "Claude analysis complete. Tokens: {} input + {} output = {} total (limit: {})",
            usage.input_tokens,
            usage.output_tokens,
            usage.total_tokens,
            self.mode.max_tokens()
        );

        Ok(analysis)
    }

    /// Build the analysis prompt for Claude
    fn build_analysis_prompt(
        &self,
        address: &str,
        contract_info: &Value,
        source_code: Option<&Value>,
        patterns: Option<&Value>,
        holder_test: Option<&Value>,
    ) -> String {
        let mut prompt = format!(
            "{}\n\n{}\n\n# Contract Analysis Request\n\n",
            self.system_prompt,
            self.mode_prompt
        );

        prompt.push_str(&format!("**Address:** {}\n\n", address));
        prompt.push_str(&format!("**Contract Info:**\n```json\n{}\n```\n\n", 
            serde_json::to_string_pretty(contract_info).unwrap_or_default()));

        if let Some(src) = source_code {
            prompt.push_str(&format!("**Verified Source Code:**\n```json\n{}\n```\n\n",
                serde_json::to_string_pretty(src).unwrap_or_default()));
        } else {
            prompt.push_str("**Source Code:** Not verified on block explorer\n\n");
        }

        if let Some(pat) = patterns {
            prompt.push_str(&format!("**Bytecode Pattern Analysis:**\n```json\n{}\n```\n\n",
                serde_json::to_string_pretty(pat).unwrap_or_default()));
        }

        if let Some(test) = holder_test {
            prompt.push_str(&format!("**Approved Holder Sell Test:**\n```json\n{}\n```\n\n",
                serde_json::to_string_pretty(test).unwrap_or_default()));
        }

        prompt.push_str("\n**Your Task:** Analyze this contract and provide a structured JSON response with your assessment.\n");
        prompt
    }

    /// Call Claude API via Anthropic's Messages API
    async fn call_claude_api(&self, mcp_client: &mut MCPClient, prompt: &str) -> Result<Value> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| DetectorError::ConfigError("ANTHROPIC_API_KEY not set".to_string()))?;

        tracing::info!("Calling Claude API...");

        // Create the HTTP client
        let client = reqwest::Client::new();

        // Prepare the request body
        let request_body = serde_json::json!({
            "model": "claude-opus-4-20250514",
            "max_tokens": 4096,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7
        });

        // Make the API call
        let response = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Claude API request failed: {}", e)))?;

        // Check response status
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_else(|_| "Unable to read error body".to_string());
            return Err(DetectorError::NetworkError(format!(
                "Claude API returned error {}: {}",
                status,
                error_body
            )));
        }

        // Parse the response
        let response_json: Value = response
            .json()
            .await
            .map_err(|e| DetectorError::NetworkError(format!("Failed to parse Claude API response: {}", e)))?;

        tracing::debug!("Claude API response: {}", serde_json::to_string_pretty(&response_json).unwrap_or_default());

        // Extract usage information for token tracking
        if let Some(usage) = response_json.get("usage") {
            let input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            
            mcp_client.update_tokens(input_tokens, output_tokens);
            
            tracing::info!(
                "Token usage - Input: {}, Output: {}, Total: {}",
                input_tokens,
                output_tokens,
                input_tokens + output_tokens
            );
        }

        // Extract the text content from Claude's response
        let content = response_json
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| DetectorError::NetworkError(
                "No text content in Claude response".to_string()
            ))?;

        tracing::debug!("Claude's analysis:\n{}", content);

        // Try to parse the response as JSON (Claude should return structured JSON)
        // Look for JSON code block first
        let json_content = if content.contains("```json") {
            // Extract JSON from code block
            content
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .map(|s| s.trim())
                .unwrap_or(content)
        } else if content.trim().starts_with('{') {
            // Already JSON
            content.trim()
        } else {
            // Try to find JSON in the response
            content
        };

        // Try to parse the content as JSON
        match serde_json::from_str::<Value>(json_content) {
            Ok(json) => Ok(json),
            Err(_) => {
                // If parsing fails, try to extract just the JSON object
                if let Some(start) = json_content.find('{') {
                    if let Some(end) = json_content.rfind('}') {
                        serde_json::from_str(&json_content[start..=end])
                            .map_err(|e| DetectorError::JsonError(e))
                    } else {
                        Err(DetectorError::NetworkError("No closing brace found in Claude response".to_string()))
                    }
                } else {
                    Err(DetectorError::NetworkError("No JSON found in Claude response".to_string()))
                }
            }
        }
    }

    /// Convert Claude findings to our Finding type
    fn convert_finding(&self, cf: ClaudeFinding) -> Finding {
        let severity = match cf.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        let category = match cf.category.to_lowercase().as_str() {
            "bytecodepattern" => Category::BytecodePattern,
            "mlpattern" => Category::MLPattern,
            "simulation" => Category::Simulation,
            "proxy" => Category::Proxy,
            "ownership" => Category::Ownership,
            "honeypot" => Category::Honeypot,
            _ => Category::BytecodePattern,
        };

        let mut finding = Finding::new(severity, category, cf.message);
        if let Some(evidence) = cf.evidence {
            finding = finding.with_evidence(evidence);
        }
        finding
    }
}

#[async_trait]
impl Analyzer for ClaudeAnalyzer {
    fn name(&self) -> &'static str {
        "claude"
    }

    fn weight(&self) -> f64 {
        0.35  // 35% weight as primary AI analyzer
    }

    fn can_analyze(&self, target: &ContractTarget) -> bool {
        // Claude can analyze any contract (with or without source code)
        target.bytecode.is_some() || target.address != ethers::types::Address::zero()
    }

    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
        let address_str = format!("{:?}", target.address);

        // Check cache first
        if let Some(cached) = self.get_cached_result(&address_str) {
            tracing::info!("Using cached Claude analysis for {}", address_str);
            return Ok(cached);
        }

        tracing::info!("Running fresh Claude analysis for {} (type: {:?})", address_str, self.analysis_type);

        // Choose analysis method based on type
        let analysis = match self.analysis_type {
            ClaudeAnalysisType::Full => {
                // Use autonomous tool-use
                match self.run_claude_analysis_with_tools(target).await {
                    Ok(analysis) => analysis,
                    Err(e) => {
                        tracing::warn!("Tool-use analysis failed: {}. Falling back to simple analysis.", e);
                        // Fall back to simple data gathering
                        self.run_claude_analysis(target).await?
                    }
                }
            },
            ClaudeAnalysisType::StaticReview => {
                // This shouldn't be called in normal flow - static review is separate
                tracing::warn!("StaticReview type should use review_static_findings() method");
                self.run_claude_analysis(target).await?
            }
        };

        // Convert to result format
        let mut result = AnalysisResult::new(analysis.risk_score);
        
        for cf in analysis.findings {
            result.add_finding(self.convert_finding(cf));
        }

        result.metadata.insert(
            "claude_reasoning".to_string(),
            serde_json::json!(analysis.reasoning)
        );
        result.metadata.insert(
            "claude_confidence".to_string(),
            serde_json::json!(analysis.confidence)
        );
        result.metadata.insert(
            "claude_mode".to_string(),
            serde_json::json!(format!("{:?}", self.mode))
        );
        result.metadata.insert(
            "claude_analysis_type".to_string(),
            serde_json::json!(format!("{:?}", self.analysis_type))
        );

        // Cache the result
        self.cache_result(&address_str, &result);

        Ok(result)
    }
}

/// Cached analysis with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedAnalysis {
    result: AnalysisResult,
    timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_mode_from_string() {
        assert_eq!(AnalysisMode::from_str("quick"), Some(AnalysisMode::Quick));
        assert_eq!(AnalysisMode::from_str("hybrid"), Some(AnalysisMode::Hybrid));
        assert_eq!(AnalysisMode::from_str("deep"), Some(AnalysisMode::Deep));
    }
}
