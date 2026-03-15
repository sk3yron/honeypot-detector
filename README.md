# PulseChain Honeypot Detector

Fast and reliable honeypot detection for PulseChain tokens powered by Claude AI via Model Context Protocol (MCP).

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
cd mcp-server && npm install && cd ..

# 2. Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Build
cargo build --release

# 4. Run with Claude AI (default: hybrid mode)
./target/release/honeypot-detector 0xYourTokenAddress
```

---

## 📋 Usage

```bash
# Basic check (uses Claude in hybrid mode - $100 budget, 15min)
./target/release/honeypot-detector 0xYourTokenAddress

# Quick mode - faster, lower cost ($50, 5min)
./target/release/honeypot-detector 0xYourTokenAddress --claude-mode=quick

# Deep mode - comprehensive analysis ($200, 30min)
./target/release/honeypot-detector 0xYourTokenAddress --claude-mode=deep

# Disable Claude (use only static + REVM simulation)
./target/release/honeypot-detector 0xYourTokenAddress --no-claude

# Custom RPC
./target/release/honeypot-detector 0xYourTokenAddress https://rpc.pulsechain.com
```

---

## 🎯 What It Detects

- ✅ Missing ERC20 functions
- ✅ Blacklist/whitelist mechanisms
- ✅ Owner privileges and admin functions
- ✅ U112 overflow traps
- ✅ Transfer restrictions
- ✅ Proxy contracts

---

## 🔍 How It Works

### Multi-Analyzer Ensemble (Weighted Voting)

1. **Claude AI Analyzer (35% weight)** - Primary AI via Model Context Protocol
   - Analyzes bytecode patterns, verified source code, and simulation results
   - Three modes: Quick, Hybrid (default), Deep
   - Graceful degradation if unavailable
   
2. **Static Analysis (25% weight)** - Bytecode pattern matching
   - Missing ERC20 functions
   - Blacklist/whitelist mechanisms
   - Owner privileges and admin functions
   
3. **REVM Simulation (25% weight)** - Live transaction testing
   - Tests actual swap execution with real holders
   - Multi-router testing (PulseX V1, V2, Piteas)
   - Historical holder scanning
   
4. **ML Analyzer (15% weight, optional)** - Neural network inference
   - Requires `--features ml-inference`

### Claude Analysis Modes

- **Quick Mode** ($50, 5min) - Fast pattern detection for obvious honeypots
- **Hybrid Mode** ($100, 15min, DEFAULT) - Adaptive analysis with escalation
- **Deep Mode** ($200, 30min) - Exhaustive SCONE-bench style analysis

---

## 📊 Example Output

### Safe Token
```
✅ APPEARS SAFE
Success Rate: 88% (22/25 holders can sell)
Admin Risk: Low
```

### Honeypot Detected
```
🔴 HONEYPOT DETECTED!
   ⚠️  DO NOT BUY THIS TOKEN!
   
Primary Issue: U112 OVERFLOW
Confidence: 95%
```

---

## ⚙️ Configuration

### Environment Variables (`.env` file)

```bash
# Required for Claude AI
ANTHROPIC_API_KEY=your_api_key_here

# MCP Server (defaults shown)
MCP_SERVER_PATH=./mcp-server/honeypot-tools.ts
PROMPTS_DIR=./prompts
CACHE_DIR=./cache

# Optional: Block explorer API for verified source code
BLOCK_EXPLORER_API_KEY=your_explorer_key

# RPC endpoint
PULSECHAIN_RPC=https://rpc.pulsechain.com

# Logging
RUST_LOG=info  # or debug for verbose output
```

### Configuration File (`config.toml`)

```toml
[detection.weights]
static = 0.25      # Bytecode pattern analysis
claude = 0.35      # Claude AI (primary)
ml = 0.15          # Machine learning (optional)
simulation = 0.25  # REVM simulation

[claude]
default_mode = "hybrid"  # quick, hybrid, or deep
enabled = true

[claude.budgets]
quick_max_tokens = 50000
hybrid_max_tokens = 100000
deep_max_tokens = 200000
```

---

## 🛠️ Development

```bash
# Run tests (Claude tests are ignored by default)
cargo test

# Run Claude-specific tests (requires setup)
cargo test --test test_claude_analyzer -- --ignored

# Run MCP server tests
cd mcp-server
npm test

# Run examples
cargo run --example test_approved_holder
cargo run --example test_swap
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Interface                        │
└───────────────────┬─────────────────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │  HoneypotDetector   │
         │  (Ensemble Voting)  │
         └─────────┬───────────┘
                   │
     ┌─────────────┼─────────────┬────────────┐
     │             │             │            │
┌────▼────┐  ┌────▼────┐  ┌─────▼────┐  ┌───▼────┐
│ Static  │  │ Claude  │  │  REVM    │  │   ML   │
│Analyzer │  │Analyzer │  │Simulator │  │Analyzer│
│  (25%)  │  │  (35%)  │  │  (25%)   │  │ (15%)  │
└─────────┘  └────┬────┘  └──────────┘  └────────┘
                  │
         ┌────────▼────────┐
         │   MCP Client    │
         │  (stdio/JSON)   │
         └────────┬────────┘
                  │
    ┌─────────────▼─────────────┐
    │  MCP Server (TypeScript)  │
    │  5 Tools:                 │
    │  - get_contract_info      │
    │  - get_source_code        │
    │  - analyze_bytecode       │
    │  - simulate_transfer      │
    │  - test_holder_sell       │
    └───────────────────────────┘
```

---

## 🔒 Disclaimer

This tool is for **research and educational purposes only**.

- Always do your own research
- Test with small amounts first
- No guarantees - use at your own risk

---

## 📚 Documentation

- **README.md** (this file) - Quick start and overview
- **[docs/](docs/)** - Complete documentation hub
  - **[User Guides](docs/user-guides/)** - Feature documentation
    - [Claude Integration](docs/user-guides/CLAUDE_INTEGRATION.md) - Setup, API reference, troubleshooting
    - [Pool Tracker Usage](docs/user-guides/POOL_TRACKER_USAGE.md) - Pool tracking features
  - **[Agentic Context](docs/agentic-context/)** - Technical docs for developers/agents
    - [Quick Reference](docs/agentic-context/QUICK_REFERENCE.md) - Fast context loading
    - [Implementation Progress](docs/agentic-context/IMPLEMENTATION_PROGRESS.md) - Architecture
    - [Integration Complete](docs/agentic-context/INTEGRATION_COMPLETE.md) - Current state
    - [Test Results](docs/agentic-context/TEST_RESULTS.md) - Testing documentation

## 📄 License

MIT

---

**Made for PulseChain** • Supports PulseX V1, V2, Piteas • Powered by Claude Opus 4.5
