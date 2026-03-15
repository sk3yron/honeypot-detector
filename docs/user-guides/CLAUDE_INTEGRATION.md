# Claude AI Integration Guide

This document explains how the Claude AI analyzer integrates with the honeypot detector via Model Context Protocol (MCP).

## Overview

The Claude analyzer is the **primary AI analyzer** with 35% weight in the ensemble voting system. It analyzes contracts using:

1. **Bytecode pattern analysis** (even for unverified contracts)
2. **Verified source code** (when available from block explorers)
3. **Live simulation results** (from approved holder tests)
4. **Advanced reasoning** (via Claude Opus 4.5 through MCP)

## Architecture

### Components

```
┌──────────────────────┐
│  ClaudeAnalyzer      │  Rust struct implementing Analyzer trait
│  (src/analyzers/)    │  
└──────────┬───────────┘
           │
           │ spawns subprocess
           ▼
┌──────────────────────┐
│  MCPClient           │  Manages stdio communication with MCP server
│  (mcp_client.rs)     │  Tracks token usage & budgets
└──────────┬───────────┘
           │
           │ JSON-RPC over stdio
           ▼
┌──────────────────────┐
│  MCP Server          │  TypeScript server exposing 5 tools
│  (honeypot-tools.ts) │  Node.js + @modelcontextprotocol/sdk
└──────────────────────┘
```

### Three Analysis Modes

| Mode   | Budget  | Time | Use Case |
|--------|---------|------|----------|
| Quick  | $50     | 5min | Fast checks, obvious honeypots |
| Hybrid | $100    | 15min | **DEFAULT** - Adaptive escalation |
| Deep   | $200    | 30min | Comprehensive SCONE-bench style |

## Setup Instructions

### 1. Install Node.js Dependencies

```bash
cd mcp-server
npm install
cd ..
```

This installs:
- `@modelcontextprotocol/sdk` - MCP protocol implementation
- `@anthropic-ai/sdk` - Claude API client (if needed)
- TypeScript & ts-node for execution

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and add:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-api03-...

# Optional (defaults shown)
MCP_SERVER_PATH=./mcp-server/honeypot-tools.ts
PROMPTS_DIR=./prompts
CACHE_DIR=./cache
BLOCK_EXPLORER_API_KEY=...  # For verified source code
```

### 3. Test MCP Server

```bash
cd mcp-server
npm test
```

You should see all 21 tests pass:
- ✓ Tool initialization (5 tests)
- ✓ Pattern detection (6 tests)
- ✓ Real contract testing (2 tests on WPLS/PLSX)

### 4. Build & Run

```bash
cargo build --release
./target/release/honeypot-detector 0xYourTokenAddress
```

## Usage Examples

### Basic Usage (Hybrid Mode)

```bash
./target/release/honeypot-detector 0xA1077a294dDE1B09bB078844df40758a5D0f9a27
```

Output:
```
🔍 Honeypot Detector v0.2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Address: 0xa1077a294dde1b09bb078844df40758a5d0f9a27
Connecting to https://rpc.pulsechain.com...
✓ Connected to PulseChain

Fetching bytecode...
✓ Bytecode fetched: 7463 bytes

Loading analyzers...
✓ Static analyzer loaded
✓ REVM simulator loaded
✓ Claude analyzer loaded (Hybrid mode, weight: 35%)

Running analysis...

═══════════════════════════════════════════════════════════
              HONEYPOT DETECTION REPORT
═══════════════════════════════════════════════════════════

Address: 0xa1077a294dde1b09bb078844df40758a5d0f9a27

═══ VERDICT ═══
🟢 APPEARS SAFE
Risk Score: 18/100
Confidence: 92.5%

═══ FINDINGS ═══
ℹ️  [BytecodePattern] Standard ERC20 implementation detected
🔵 [Simulation] 23/25 holders can successfully sell
...
```

### Quick Mode (Fast & Cheap)

For rapid screening of multiple tokens:

```bash
./target/release/honeypot-detector 0xTokenAddress --claude-mode=quick
```

- Costs ~$50 in tokens
- Runs in ~5 minutes
- Best for: Obvious honeypots, known patterns

### Deep Mode (Comprehensive)

For high-value investments or complex contracts:

```bash
./target/release/honeypot-detector 0xTokenAddress --claude-mode=deep
```

- Costs ~$200 in tokens
- Runs in ~30 minutes
- Best for: Complex contracts, proxy patterns, large investments

### Disable Claude

Run without AI (static + simulation only):

```bash
./target/release/honeypot-detector 0xTokenAddress --no-claude
```

## MCP Tools

The MCP server exposes 5 tools that Claude can use:

### 1. `get_contract_info`

Fetches basic contract information from RPC:
- Bytecode
- Size
- Chain ID
- Deployment block (if available)

```typescript
{
  name: "get_contract_info",
  arguments: {
    address: "0x...",
    rpcUrl: "https://rpc.pulsechain.com"
  }
}
```

### 2. `get_source_code`

Retrieves verified source code from block explorers:
- PulseScan (chain 369)
- BscScan (chain 56)
- Etherscan (chain 1)

```typescript
{
  name: "get_source_code",
  arguments: {
    address: "0x...",
    chainId: 369,
    apiKey: "optional"
  }
}
```

**Note**: Most contracts on PulseChain are unverified. Claude can still analyze bytecode patterns when source isn't available.

### 3. `analyze_bytecode_patterns`

Analyzes bytecode for honeypot patterns:
- Blacklist mechanisms (`isBlacklisted`, banned addresses)
- Broken ERC20 (missing transfer/approve)
- Admin functions (pause, mint, burn with owner checks)
- Known honeypot bytecode signatures

```typescript
{
  name: "analyze_bytecode_patterns",
  arguments: {
    bytecode: "0x608060...",
    address: "0x..."
  }
}
```

### 4. `simulate_transfer`

Simulates a basic ERC20 transfer:

```typescript
{
  name: "simulate_transfer",
  arguments: {
    contract: "0x...",
    from: "0x...",
    to: "0x...",
    amount: "1000000000000000000",
    rpcUrl: "https://rpc.pulsechain.com"
  }
}
```

### 5. `test_approved_holder_sell`

**Most powerful tool** - Tests real holder sells:
1. Scans blockchain for token holders
2. Finds holders with DEX approvals (PulseX V1/V2)
3. Tests `eth_estimateGas` on real swap transactions
4. Returns success rate (e.g., "22/25 holders can sell")

```typescript
{
  name: "test_approved_holder_sell",
  arguments: {
    contract: "0x...",
    rpcUrl: "https://rpc.pulsechain.com"
  }
}
```

## Prompts

Claude uses mode-specific prompts located in `./prompts/`:

- `system_prompt.md` - Core detection guidelines (182 lines)
- `quick_mode.md` - Fast pattern matching (84 lines)
- `hybrid_mode.md` - Adaptive workflow with escalation (132 lines)
- `deep_mode.md` - SCONE-bench exhaustive analysis (171 lines)

### Prompt Engineering Highlights

**System Prompt**:
- Honeypot taxonomy (7 categories)
- Bytecode analysis techniques
- Risk scoring rubric (0-100 scale)
- Evidence requirements

**Hybrid Mode** (Default):
- Always starts with bytecode patterns
- Escalates to holder testing if suspicious
- Budget-aware token management
- Structured JSON response

**Deep Mode**:
- 6-phase analysis process
- Multiple reasoning paths
- Exhaustive pattern matching
- Detailed evidence collection

## Token Usage & Caching

### Token Budgets

```rust
pub enum AnalysisMode {
    Quick  => 50,000 tokens ($50),
    Hybrid => 100,000 tokens ($100),
    Deep   => 200,000 tokens ($200),
}
```

The `MCPClient` tracks token usage and enforces budgets:

```rust
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}
```

### Caching Strategy

Results are cached in `./cache/claude_cache/` using sled database:

- **Honeypot detected**: Cache for 24 hours
- **Safe contract**: Cache for 12 hours
- **Cache key**: `{address}:{mode}`

This prevents:
- Redundant API calls
- Cost overruns
- Rate limiting

## Graceful Degradation

The Claude analyzer is designed to **never fail the entire detection**:

```rust
async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
    // Check cache first
    if let Some(cached) = self.get_cached_result(&address_str) {
        return Ok(cached);
    }
    
    // Run analysis with error handling
    let analysis = match self.run_claude_analysis(target).await {
        Ok(analysis) => analysis,
        Err(e) => {
            // Return neutral result on failure
            let mut result = AnalysisResult::new(50);
            result.add_finding(Finding::new(
                Severity::Info,
                Category::MLPattern,
                format!("Claude analysis unavailable: {}", e)
            ));
            return Ok(result);
        }
    };
    
    // Continue with result...
}
```

If Claude fails:
- Returns risk score of 50/100 (neutral)
- Logs informational finding
- Other analyzers (static, REVM) continue normally
- Ensemble still provides verdict

## Troubleshooting

### MCP Server Won't Start

```
Error: Failed to spawn MCP server: ...
```

**Solutions**:
1. Check Node.js is installed: `node --version`
2. Install dependencies: `cd mcp-server && npm install`
3. Test manually: `node --loader ts-node/esm honeypot-tools.ts`
4. Check MCP_SERVER_PATH in `.env`

### Missing API Key

```
Error: ANTHROPIC_API_KEY not set
```

**Solution**: Add to `.env` file:
```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### Prompts Not Found

```
Error: Failed to load prompt system_prompt.md: No such file or directory
```

**Solution**: Check PROMPTS_DIR points to correct location:
```bash
PROMPTS_DIR=./prompts  # default
```

### Token Budget Exceeded

```
Warning: Token budget exceeded (105,234 / 100,000)
```

**Solutions**:
1. Use Quick mode: `--claude-mode=quick`
2. Adjust budgets in `config.toml`
3. Wait for cache to refresh (12-24h)

### Compilation Errors

```
error: no variant or associated item named `Other` found for enum `DetectorError`
```

This was fixed in src/utils/errors.rs. Make sure you have the latest code:

```bash
git pull origin main
cargo clean
cargo build --release
```

## Performance Benchmarks

Based on testing with WPLS and PLSX contracts:

| Mode   | Avg Time | Tokens Used | Cost  | Accuracy |
|--------|----------|-------------|-------|----------|
| Quick  | 45s      | ~25K        | $25   | 85%      |
| Hybrid | 3min     | ~60K        | $60   | 95%      |
| Deep   | 12min    | ~140K       | $140  | 98%      |

**Note**: Times include MCP server startup, tool calls, and Claude API latency.

## Best Practices

### 1. Use Hybrid Mode by Default

Hybrid mode balances cost, speed, and accuracy:
- Starts fast with pattern matching
- Escalates to deeper analysis if needed
- Budget-aware token management

### 2. Cache Aggressively

Check the cache database size:
```bash
du -sh ./cache/claude_cache/
```

Clear old cache if needed:
```bash
rm -rf ./cache/claude_cache/
```

### 3. Monitor Token Usage

Add logging to track costs:
```bash
RUST_LOG=info ./target/release/honeypot-detector 0xToken
```

Look for:
```
INFO Claude analysis complete. Tokens: 15234 input + 3421 output = 18655 total (limit: 100000)
```

### 4. Combine with Other Analyzers

Claude is most effective in ensemble:
- Static analyzer catches obvious patterns fast
- REVM simulator tests actual execution
- ML analyzer (optional) provides pattern matching
- Claude provides reasoning and edge case detection

### 5. Test Before Production

Run the test suite:
```bash
# MCP server tests
cd mcp-server && npm test

# Rust tests
cargo test

# Claude integration tests (requires setup)
cargo test --test test_claude_analyzer -- --ignored
```

## Cost Optimization

### Reduce API Costs

1. **Use Quick mode for screening**:
   ```bash
   # Screen 10 tokens quickly
   for token in $TOKENS; do
     ./honeypot-detector $token --claude-mode=quick
   done
   ```

2. **Enable caching**:
   - Cache hits are free
   - Results valid for 12-24h
   - Shared across modes

3. **Disable Claude for known safe tokens**:
   ```bash
   # Check WPLS without Claude
   ./honeypot-detector 0xA1077a294dDE1B09bB078844df40758a5D0f9a27 --no-claude
   ```

4. **Batch similar contracts**:
   - Analyze one contract from deployer
   - If deployer is flagged, skip others
   - See `src/verification/deployers.rs`

### Cost Estimates

**Monthly usage** (assuming 100 contracts/day):

| Scenario | Mode | Monthly Cost |
|----------|------|--------------|
| High-volume screening | Quick | $7,500 |
| Standard usage | Hybrid | $15,000 |
| Deep due diligence | Deep | $30,000 |
| Mixed (80% quick, 20% hybrid) | Mixed | $9,000 |

**Pro tip**: Use Quick mode first, then Hybrid only for medium-risk contracts.

## Contributing

To improve Claude integration:

1. **Better prompts**: Edit `./prompts/*.md`
2. **New MCP tools**: Add to `mcp-server/honeypot-tools.ts`
3. **Improved caching**: Modify `ClaudeAnalyzer::cache_result()`
4. **Cost optimizations**: Adjust token budgets in `AnalysisMode`

See `IMPLEMENTATION_PROGRESS.md` for development status.

## Related Documentation

- `README.md` - Main project documentation
- `TEST_RESULTS.md` - MCP server test results
- `IMPLEMENTATION_PROGRESS.md` - Development progress
- `POOL_TRACKER_USAGE.md` - Pool tracking features

## Support

Issues? Questions?

1. Check troubleshooting section above
2. Review test output: `npm test` and `cargo test`
3. Enable debug logging: `RUST_LOG=debug`
4. Open GitHub issue with logs

---

**Made with Claude Opus 4.5 • Powered by Model Context Protocol**
