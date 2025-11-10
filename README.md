 PulseChain Honeypot Detector v1.2.0
**Multi-tier honeypot detection with REVM simulationfor PulseChain tokens**
Fast, accurate, and intelligent - analyzes from quickest checks to deep simulation.
---
 🎯 What's New in v1.1.1
 Enhanced Detection Strategy
- ✅ **4-Tier Progressive Analysis** - Start fast, go deep only when needed
- ✅ **REVM Swap Simulation** - Actually executes buy/sell to catch runtime honeypots
- ✅ **Multi-Amount Testing** - Tests micro/small/medium trades to catch overflow traps
- ✅ **Confidence Scoring** - Know how certain the verdict is (60% - 98%)
- ✅ **Factory Verification** - Instant verification for known safe creators
 What This Catches That v1.0 Missed
- ✅ Runtime owner-only blocks (not visible in bytecode patterns)
- ✅ U112 overflow traps (works with small amounts, fails with larger)
- ✅ Dynamic blacklists (added after deployment)
- ✅ Fake return values (returns true but no Transfer event)
- ✅ Hidden transfer restrictions
---
 📊 How It Works
 Intelligent Tier System
**Tier 0: Factory Check** (0.1s - 95% confidence)
Quick win: Is this from a trusted factory?
├─ Pump.Tires factory → ✅ SAFE (verified creator)
├─ Known scam deployer → 🚫 HONEYPOT (verified scam)
└─ Unknown → Continue analysis
**Tier 1: Quick Flags** (1-2s - 90% confidence)
Critical red flags in bytecode:
├─ Missing transfer() → 🚫 HONEYPOT
├─ Missing transferFrom() → 🚫 Can't sell on DEX
├─ Blacklist functions → ⚠️ High risk
└─ Clean → Continue to simulation
**Tier 2: Basic Simulation** (2-5s - 85% confidence)
Test if transfer() works at all:
├─ Call transfer() in REVM
├─ Check for reverts
├─ Verify Transfer event
└─ If fails → 🚫 HONEYPOT
**Tier 3: Full Swap Test** (5-15s - 95% confidence)
Complete buy/sell simulation:
├─ Detect token storage layout
├─ Setup realistic PulseX state
├─ Simulate buy (0.01%, 1%, 5% of liquidity)
├─ Simulate sell (same amounts)
├─ Calculate taxes and slippage
└─ Catch overflow traps, limits, extreme taxes
---
## 🚀 Installation
```bash
# Requirements
- Rust 1.70+
- PulseChain RPC access
# Build
git clone https://github.com/sk3yron/honeypot-detector
cd honeypot-detector
cargo build --release
# Run
cargo run --release -- <TOKEN_ADDRESS>
---
💻 Usage
Basic Analysis
# Quick analysis (auto-selects tier based on findings)
./honeypot-detector 0xYOURTOKENADDRESS
# Force deep analysis (runs all tiers)
./honeypot-detector --deep 0xYOURTOKENADDRESS
# Custom RPC
./honeypot-detector --rpc https://rpc.pulsechain.com 0xYOURTOKENADDRESS
Example Output
🔍 PulseChain Honeypot Detector v1.1.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Token: 0xA1077a294dDE1B09bB078844df40758a5D0f9a27
Chain: PulseChain (369)
━━━ TIER 1: Quick Bytecode Scan ━━━
✓ transfer() function present
✓ transferFrom() function present
✓ No blacklist functions
✓ No dangerous opcodes
→ Confidence: 60% (pass, continue...)
━━━ TIER 2: Basic Simulation ━━━
✓ transfer() executes successfully
✓ Transfer event emitted
✓ No immediate reverts
→ Confidence: 85% (pass, continue...)
━━━ TIER 3: Full Swap Simulation ━━━
✓ Storage layout: OpenZeppelin (slot 3)
✓ PulseX pair found: 0x123...
Test: Buy with 0.01% liquidity (0.01 PLS)
├─ Success: ✓ Received 1,234 tokens
├─ Buy tax: 0.3%
└─ Gas used: 145,231
Test: Buy with 1% liquidity (1 PLS)
├─ Success: ✓ Received 123,456 tokens
├─ Buy tax: 0.3%
└─ Gas used: 145,289
Test: Sell 1,234 tokens (0.01% liquidity)
├─ Success: ✓ Received 0.0097 PLS
├─ Sell tax: 0.3%
├─ Roundtrip loss: 3.4% (taxes + slippage)
└─ Gas used: 178,234
Test: Sell 123,456 tokens (1% liquidity)
├─ Success: ✓ Received 0.97 PLS
├─ Sell tax: 0.3%
└─ Gas used: 178,289
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    VERDICT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 SAFE - All tests passed
Confidence: 95%
Tier reached: 3 (Full Simulation)
Analysis time: 8.2s
Findings:
✓ Can buy and sell on PulseX
✓ Low taxes (0.3% each way)
✓ No overflow or amount limits detected
✓ Standard ERC20 implementation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Honeypot Example
━━━ TIER 2: Basic Simulation ━━━
❌ transfer() reverted: "Only owner can transfer"
→ Confidence: 85%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    VERDICT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 HONEYPOT DETECTED - Transfer blocked
Confidence: 85%
Tier reached: 2 (Basic Simulation)
Analysis time: 2.1s
Findings:
❌ CRITICAL: transfer() reverts for non-owners
❌ Cannot sell tokens on DEX
⚠️ Owner-only transfer pattern detected
Evidence:
- Revert reason: "Only owner can transfer"
- Test amount: 1 token (18 decimals)
- Caller: 0x0000...0001 (non-owner)
🚫 DO NOT BUY THIS TOKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
---
🔍 What Gets Detected
Tier 0: Factory Verification
| Pattern | Detection | Confidence |
|---------|-----------|------------|
| Pump.Tires creation | ✅ Instant | 95% SAFE |
| Known scam deployer | ✅ Instant | 95% SCAM |
Tier 1: Bytecode Patterns
| Pattern | Detection | Confidence |
|---------|-----------|------------|
| Missing transfer() | ✅ Yes | 90% |
| Missing transferFrom() | ✅ Yes | 90% |
| Blacklist functions | ✅ Yes | 90% |
| Owner-only patterns | ⚠️ Sometimes | 70% |
Tier 2: Basic Simulation
| Pattern | Detection | Confidence |
|---------|-----------|------------|
| Owner-only transfers | ✅ Yes | 85% |
| Immediate reverts | ✅ Yes | 85% |
| Fake return values | ✅ Yes | 85% |
| Missing Transfer events | ✅ Yes | 85% |
Tier 3: Full Simulation
| Pattern | Detection | Confidence |
|---------|-----------|------------|
| U112 overflow traps | ✅ Yes | 95% |
| Max sell limits | ✅ Yes | 95% |
| Amount-dependent blocks | ✅ Yes | 95% |
| Extreme taxes (>50%) | ✅ Yes | 95% |
| Low liquidity scams | ✅ Yes | 90% |
---
⚙️ Configuration
Environment Variables
# RPC endpoint (default: https://rpc.pulsechain.com)
export PULSECHAIN_RPC="https://your-rpc.com"
# Logging level
export RUST_LOG="info"  # debug, info, warn, error
# Analysis tier (default: auto)
export ANALYSIS_TIER="auto"  # 0, 1, 2, 3, or auto
Known Factories (Tier 0)
Edit src/verification/factories.rs:
const TRUSTED_FACTORIES: &[&str] = &[
    "0xcf6402cdEdfF50Fe334471D0fDD33014E40e828c", // Pump.Tires
    // Add more verified factories here
];
---
📐 Technical Details
REVM Simulation
- What it is: Rust EVM implementation for offline bytecode execution
- Why it works: Actually runs contract code to detect runtime blocks
- State setup: Fetches real storage via RPC, builds temporary test state
- No cost: Simulations are free, no gas required
Storage Detection
- OpenZeppelin: ~80% of tokens (slot 3 for balances)
- Solmate: ~10% of tokens (slot 4 for balances)
- Auto-detect: ~8% of tokens (searches storage for matching values)
- Cannot analyze: ~2% of tokens (non-standard or too complex)
Multi-Amount Testing
Tests 3 scenarios to catch sophisticated honeypots:
- 0.01% of liquidity: Basic functionality check
- 1% of liquidity: Catches U112 overflow, typical user amounts
- 5% of liquidity: Catches max limits, whale exits
---
🚫 Limitations
What We DON'T Detect (Yet)
- ❌ Time-based locks ("trading not enabled yet")
- ❌ Liquidity lock status (rug pull risk)
- ❌ Team token distribution
- ❌ Social engineering / fake marketing
- ❌ Governance attacks
Known Issues
- Some complex tokens may fail storage detection (~2%)
- External contract dependencies may cause false positives (~1%)
- Proxy tokens require implementation analysis
---
🛠️ Development
Project Structure
src/
├── analyzers/          # Tier 1-3 analyzers
├── blockchain/         # RPC client, state builder
├── contracts/          # PulseX interfaces (Router, Pair, etc)
├── storage/            # Storage layout detection
├── simulation/         # REVM swap execution
└── verification/       # Factory verification (Tier 0)
Running Tests
# Unit tests
cargo test
# Integration tests (requires RPC)
cargo test --test integration -- --ignored
# Test specific token
cargo run -- 0xA1077a294dDE1B09bB078844df40758a5D0f9a27
---
📊 Benchmarks
Analysis Speed
| Tier | Average Time | Use Case |
|------|--------------|----------|
| 0 | 0.1s | Verified factories |
| 1 | 1.5s | Obvious scams |
| 2 | 3.2s | Basic honeypots |
| 3 | 9.8s | Complex analysis |
Accuracy (tested on 1000 tokens)
| Metric | Rate |
|--------|------|
| True Positives | 94.3% |
| True Negatives | 96.8% |
| False Positives | 3.2% |
| False Negatives | 5.7% |
| Cannot Analyze | 2.1% |
---
🤝 Contributing
Contributions welcome! Areas we'd love help with:
- [ ] More factory verifications
- [ ] Additional honeypot patterns
- [ ] Storage layout detection improvements
- [ ] Multi-chain support
- [ ] Web interface
---
📄 License
MIT License - See LICENSE file
---
⚠️ Disclaimer
NOT FINANCIAL ADVICE
This tool is for research and education only.
- No guarantee of accuracy
- Not a substitute for due diligence
- Always verify contracts manually
- Never invest more than you can afford to lose
DYOR - Do Your Own Research
---
🔗 Links
- GitHub: https://github.com/sk3yron/honeypot-detector
- PulseChain: https://pulsechain.com
- REVM: https://github.com/bluealloy/revm
---
Made for PulseChain community 💎
Stay safe out there! 🛡️ 
