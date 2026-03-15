# Quick Reference for AI Agents

⚡ **Fast context loading for agents continuing development**

## 🎯 Current State (December 4, 2025)

**Phase**: 5 Complete → Phase 6 Ready  
**Status**: 85% Complete  
**Build**: ✅ Compiles (16 warnings, 0 errors)  
**Tests**: ✅ 21/21 MCP tests passing

## 🚨 Critical TODO (Phase 6)

**Location**: `src/analyzers/claude_analyzer.rs:225`

```rust
async fn call_claude_api(&self, _mcp_client: &MCPClient, prompt: &str) -> Result<Value> {
    // TODO: Actually call Claude API via MCP
    // Currently returns MOCK DATA
}
```

**Required**: Implement real Claude API integration via MCP (~2-3 hours)

## 📂 Project Structure

```
honeypot-detector/
├── src/
│   ├── analyzers/
│   │   ├── claude_analyzer.rs    ← Claude integration (348 lines)
│   │   ├── mcp_client.rs         ← MCP subprocess manager (306 lines)
│   │   ├── static_analyzer.rs    ← Bytecode patterns
│   │   ├── simulator.rs          ← REVM simulation
│   │   └── ml_analyzer.rs        ← Neural net (optional)
│   ├── main.rs                   ← CLI entry point
│   └── ...
│
├── mcp-server/
│   ├── honeypot-tools.ts         ← MCP server (622 lines, 5 tools)
│   └── test-*.ts                 ← Tests (21 passing)
│
├── prompts/
│   ├── system_prompt.md          ← Core guidelines (182 lines)
│   ├── quick_mode.md             ← Fast mode (84 lines)
│   ├── hybrid_mode.md            ← Adaptive (132 lines)
│   └── deep_mode.md              ← Exhaustive (171 lines)
│
└── docs/agentic-context/         ← You are here
    ├── IMPLEMENTATION_PROGRESS.md
    ├── INTEGRATION_COMPLETE.md
    └── TEST_RESULTS.md
```

## 🔧 Key Components

### 1. ClaudeAnalyzer (Rust)
- **Path**: `src/analyzers/claude_analyzer.rs`
- **Weight**: 35% (primary AI)
- **Implements**: `Analyzer` trait
- **Caching**: 24h honeypots, 12h safe
- **Graceful Degradation**: Returns neutral score (50/100) on failure

### 2. MCPClient (Rust)
- **Path**: `src/analyzers/mcp_client.rs`
- **Function**: Manages MCP server subprocess
- **Communication**: stdio JSON-RPC
- **Tracking**: Token usage & budgets
- **Modes**: Quick (50K tokens), Hybrid (100K), Deep (200K)

### 3. MCP Server (TypeScript)
- **Path**: `mcp-server/honeypot-tools.ts`
- **Runtime**: Node.js + ts-node
- **Tools**: 5 (contract info, source code, patterns, simulate, holder test)
- **Tests**: 21/21 passing (<3s performance)

### 4. Prompts (Markdown)
- **Path**: `prompts/*.md`
- **Total**: 569 lines across 4 files
- **System**: Core detection taxonomy
- **Modes**: Quick/Hybrid/Deep strategies

## 🏗️ Architecture

```
CLI (main.rs)
  └─> HoneypotDetector (ensemble voting)
       ├─> StaticAnalyzer (25%)
       ├─> SimulatorAnalyzer (25%)
       ├─> MLAnalyzer (15%, optional)
       └─> ClaudeAnalyzer (35%) ★ PRIMARY
            └─> MCPClient (stdio)
                 └─> MCP Server (TypeScript)
                      └─> 5 Tools for Claude
```

## 🛠️ Common Tasks

### Start Development Session

```bash
cd /home/egftdlnx/projects/honeypot-detector

# Read context
cat docs/agentic-context/INTEGRATION_COMPLETE.md
cat docs/agentic-context/IMPLEMENTATION_PROGRESS.md

# Check build
cargo check

# Run tests
cargo test
cd mcp-server && npm test && cd ..
```

### Make Changes

```bash
# Edit code
vim src/analyzers/claude_analyzer.rs

# Test compilation
cargo check

# Run specific test
cargo test --test test_claude_analyzer

# Update docs
vim docs/agentic-context/IMPLEMENTATION_PROGRESS.md
```

### Add New Feature

1. Read `IMPLEMENTATION_PROGRESS.md` for architecture
2. Make code changes
3. Add tests
4. Update `IMPLEMENTATION_PROGRESS.md` with changes
5. Update root `README.md` if user-facing

## 📋 File Responsibilities

| File | Purpose | Update When |
|------|---------|-------------|
| Root `README.md` | User docs | Adding user features |
| `CLAUDE_INTEGRATION.md` | Claude setup | Changing Claude integration |
| `docs/agentic-context/IMPLEMENTATION_PROGRESS.md` | Architecture | Major code changes |
| `docs/agentic-context/INTEGRATION_COMPLETE.md` | Status | Completing phases |
| `docs/agentic-context/TEST_RESULTS.md` | Testing | Test changes |

## 🔍 Finding Things

### "Where is X implemented?"

```bash
# Find in code
rg "ClaudeAnalyzer" --type rust

# Find in docs
rg "ClaudeAnalyzer" docs/agentic-context/

# Find all references
rg "call_claude_api" 
```

### "How does X work?"

1. Check `IMPLEMENTATION_PROGRESS.md` first
2. Read code comments
3. Check Git history: `git log --all --full-history -- path/to/file`

### "What's the current status?"

Read `INTEGRATION_COMPLETE.md` - it's the source of truth for current state.

## 🐛 Debugging

### Build Errors

```bash
# Clean rebuild
cargo clean && cargo build

# Check specific module
cargo check --lib

# Verbose errors
cargo build 2>&1 | less
```

### MCP Server Issues

```bash
cd mcp-server

# Test manually
node --loader ts-node/esm honeypot-tools.ts

# Run tests
npm test

# Check dependencies
npm install
```

### Runtime Issues

```bash
# Enable debug logging
RUST_LOG=debug ./target/debug/honeypot-detector 0xToken

# Test specific analyzer
RUST_LOG=honeypot_detector::analyzers::claude_analyzer=trace
```

## 📊 Important Numbers

| Metric | Value |
|--------|-------|
| Total Lines Added | ~2,640 |
| Rust Code | ~650 lines |
| TypeScript Code | ~800 lines |
| Documentation | ~1,500 lines |
| MCP Tests | 21 passing |
| Analyzer Weight | 35% (Claude) |
| Token Budgets | 50K/100K/200K |
| Cache TTL | 12-24 hours |

## 🚀 Phase 6 Implementation Guide

**Goal**: Make Claude API calls real (not mock)

**Location**: `src/analyzers/claude_analyzer.rs:225-245`

**Current**:
```rust
async fn call_claude_api(&self, _mcp_client: &MCPClient, prompt: &str) -> Result<Value> {
    tracing::warn!("Claude API call not yet implemented - returning mock data");
    Ok(serde_json::json!({ "risk_score": 25, ... }))
}
```

**Needed**:
1. Call Claude API via MCP's `use_mcp_tool`
2. Pass prompt with system + mode context
3. Parse JSON response from Claude
4. Extract token usage from API response
5. Handle errors gracefully

**Estimated Time**: 2-3 hours

**Dependencies**:
- MCP SDK already installed
- Anthropic API key in `.env`
- Prompts already written

## 🎓 Learning the Codebase

### First Hour
1. Read `INTEGRATION_COMPLETE.md` (10 min)
2. Read `IMPLEMENTATION_PROGRESS.md` Phase 1-5 (20 min)
3. Browse `src/analyzers/claude_analyzer.rs` (15 min)
4. Run tests: `cargo test && cd mcp-server && npm test` (15 min)

### Deep Dive
1. Read all 4 prompt files in `prompts/` (30 min)
2. Study MCP server `mcp-server/honeypot-tools.ts` (30 min)
3. Trace analyzer execution in `src/main.rs` (20 min)
4. Review test results in `TEST_RESULTS.md` (10 min)

## 📞 Help & Context

**Architecture Questions**: `IMPLEMENTATION_PROGRESS.md`  
**Current Status**: `INTEGRATION_COMPLETE.md`  
**Testing Info**: `TEST_RESULTS.md`  
**User Setup**: Root `CLAUDE_INTEGRATION.md`  
**Quick Start**: Root `README.md`

## ✅ Development Checklist

Before making changes:
- [ ] Read relevant docs from `docs/agentic-context/`
- [ ] Check current build status: `cargo check`
- [ ] Review related code sections
- [ ] Check test coverage

After making changes:
- [ ] Code compiles: `cargo check`
- [ ] Tests pass: `cargo test`
- [ ] Updated `IMPLEMENTATION_PROGRESS.md` if architectural
- [ ] Updated `INTEGRATION_COMPLETE.md` if completing TODO
- [ ] Updated root docs if user-facing
- [ ] Git commit with clear message

---

**Last Updated**: December 4, 2025  
**Next Phase**: Phase 6 - Claude API Implementation  
**Agent Tip**: Always read `INTEGRATION_COMPLETE.md` first for current state
