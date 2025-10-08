# Honeypot Detector v2.0.0

Fast and reliable ERC20 honeypot detection using static bytecode analysis.

**⚡ Analyzes tokens in 2-5 seconds** - no simulation needed!

---

## 🎯 What It Does

Scans smart contract bytecode to identify malicious patterns:

1. ✅ Detects blacklist functions
2. ✅ Finds missing ERC20 functions
3. ✅ Identifies honeypot signatures
4. ✅ Analyzes proxy contracts
5. ✅ Checks for dangerous opcodes
6. ✅ Evaluates ownership risks

**Risk Scoring:** 0-100 scale with clear SAFE/LOW/MEDIUM/HIGH/CRITICAL ratings

---

## 📊 Version History

### v2.0.0 (Current) - Static Analyzer
- **Fast:** 2-5 seconds per token
- **Accurate:** Pattern-based detection
- **Smart:** Proxy contract support
- **Efficient:** Bytecode caching

### v1.0.0 (Deprecated) - Transaction Simulator
- ❌ Could not detect real honeypots
- ❌ Slow (30-60s per analysis)
- ❌ Required Anvil fork
- **Status:** Replaced with v2.0.0

---

## 🚀 Installation

```bash
# Install Foundry (required for cast)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Clone repository
git clone https://github.com/sk3yron/honeypot-detector
cd honeypot-detector

# Make executable
chmod +x honeypot-detector.sh
```

### Verify Installation
```bash
cast --version  # Should show foundry version
```

---

## 💻 Usage

### Basic Analysis
```bash
./honeypot-detector.sh 0xTOKENADDRESS
```

### Verbose Mode (Show All Details)
```bash
./honeypot-detector.sh -v 0xTOKENADDRESS
```

### Custom RPC Endpoint
```bash
./honeypot-detector.sh --rpc https://rpc.pulsechain.com 0xTOKENADDRESS
```

### Environment Variable
```bash
RPC_URL="https://custom-rpc.com" ./honeypot-detector.sh 0xTOKENADDRESS
```

---

## 📋 Example Output

### ✅ Safe Token
```
════════════════════════════════════════════════════
         HONEYPOT DETECTOR - PRODUCTION             
════════════════════════════════════════════════════

Token Information:
  Address:  0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
  Name:     HEX
  Symbol:   HEX
  Decimals: 8
  Supply:   4778703663763402918

✓ No honeypot patterns detected

This contract appears to be safe based on bytecode analysis.
Standard ERC20 functions are present.

Risk Assessment:
  Score: 20 / 100
  Level: SAFE

✓ APPEARS SAFE
No honeypot patterns detected.
Contract follows standard ERC20 conventions.
```

### ⚠️ Honeypot Detected
```
════════════════════════════════════════════════════
         HONEYPOT DETECTOR - PRODUCTION             
════════════════════════════════════════════════════

Token Information:
  Address:  0x1234567890abcdef1234567890abcdef12345678
  Name:     ScamToken
  Symbol:   SCAM
  Decimals: 18
  Supply:   1000000000000000000000000

Security Findings:

  [CRITICAL] BLACKLIST: isBlacklisted() function detected
  [CRITICAL] HONEYPOT: approve() exists but NO transferFrom()
  [MEDIUM] PRIVILEGE: mint() function exists

Risk Assessment:
  Score: 90 / 100
  Level: CRITICAL

⛔ CRITICAL RISK - LIKELY HONEYPOT/SCAM
Strong honeypot indicators detected. DO NOT USE.
```

---

## 🔍 What It Detects

### Critical Patterns (High Risk)
| Pattern | Description | Risk Score |
|---------|-------------|------------|
| `isBlacklisted()` | Blacklist function present | +60 |
| `addBlackList()` | Can add addresses to blacklist | +60 |
| Missing `transfer()` | No transfer function | +70 |
| `approve()` without `transferFrom()` | Classic honeypot signature | +80 |

### Medium Risk Patterns
| Pattern | Description | Risk Score |
|---------|-------------|------------|
| `mint()` | Owner can create tokens | +10 |
| `burn()` | Can destroy tokens | +10 |
| Multiple `DELEGATECALL` | Proxy pattern or exploit risk | +15 |

### Low Risk Patterns
| Pattern | Description | Risk Score |
|---------|-------------|------------|
| Has owner | Centralized control | +5 |
| `SELFDESTRUCT` | Can destroy contract | +10 |

### Positive Indicators
| Pattern | Description | Risk Score |
|---------|-------------|------------|
| Ownership renounced | No central control | -5 |

---

## 🎭 Proxy Detection

Automatically detects and analyzes implementation contracts:

- **EIP-1167** Minimal Proxy (Clone)
- **EIP-1967** Transparent/UUPS Proxy

When a proxy is detected, the tool:
1. Identifies the implementation address
2. Fetches implementation bytecode
3. Analyzes the actual logic contract
4. Reports findings from both contracts

---

## ⚙️ Configuration

### Environment Variables

```bash
# RPC endpoint (default: https://rpc.pulsechain.com)
export RPC_URL="https://your-rpc-endpoint.com"

# Enable verbose logging
export VERBOSE=true
```

### Cache Settings

Bytecode is cached for **1 hour** by default to speed up repeated analyses.

Cache location: `./.cache/`

To clear cache:
```bash
rm -rf .cache/
```

---

## 🚦 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Safe (risk score < 36.9) |
| `1` | High/Critical risk detected |
| `2` | Error (invalid input, RPC failure, etc.) |

### Using in Scripts
```bash
#!/bin/bash

if ./honeypot-detector.sh 0xTOKEN; then
    echo "Token is safe, proceeding..."
else
    echo "Token is risky, aborting!"
    exit 1
fi
```

---

## 🔧 Troubleshooting

### Error: 'cast' not found
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify
cast --version
```

### Error: No working RPC
```bash
# Test RPC manually
cast block-number --rpc-url https://rpc.pulsechain.com

# Try fallback
./honeypot-detector.sh --rpc https://pulsechain.publicnode.com 0xTOKEN
```

### Error: Not a contract
```bash
# Verify address is a contract
cast code 0xTOKENADDRESS --rpc-url https://rpc.pulsechain.com

# Check if you copied the full address (0x + 40 hex chars)
```

### Slow performance
```bash
# Check if cache is working
ls -la .cache/

# Clear old cache
find .cache/ -mtime +1 -delete

# Use faster RPC endpoint
export RPC_URL="https://faster-rpc.com"
```

---

## ⚠️ Limitations

This tool **does NOT detect**:

- ❌ **High tax tokens** (>50% buy/sell fees) - bytecode analysis can't determine exact tax rates
- ❌ **Low liquidity** - doesn't check DEX pairs or liquidity amounts
- ❌ **Time-based locks** - "trading not enabled yet" mechanisms
- ❌ **Sophisticated runtime honeypots** - novel exploit techniques
- ❌ **Social engineering** - fake team, misleading marketing
- ❌ **Rug pull risks** - liquidity lock status, team tokens

### What It DOES Detect Well:

- ✅ Blacklist/whitelist functions
- ✅ Missing core ERC20 functions
- ✅ Obvious honeypot patterns
- ✅ Malicious proxy implementations
- ✅ Dangerous privilege functions

---

## 🎯 Best Practices

### Before Trading Any Token:

1. ✅ Run this tool first (quick check)
2. ✅ Verify source code on block explorer
3. ✅ Check liquidity lock status
4. ✅ Review audit reports (if available)
5. ✅ Check team background
6. ✅ Test with small amount first
7. ✅ Use reputable DEX aggregators

### Interpreting Results:

- **SAFE** ✅ - No red flags, but still DYOR
- **LOW** ⚠️ - Minor concerns, review manually
- **MEDIUM** ⚠️ - Significant risks, verify source code
- **HIGH** 🚫 - Serious concerns, avoid unless verified
- **CRITICAL** 🛑 - Likely scam, DO NOT USE

---

## 📚 Technical Details

### How It Works

1. **Fetch Bytecode** - Downloads contract bytecode via RPC
2. **Detect Proxy** - Checks for EIP-1167/1967 proxy patterns
3. **Pattern Matching** - Scans for malicious function selectors
4. **Risk Scoring** - Aggregates findings into 0-100 score
5. **Classification** - Maps score to risk level

### Function Selectors Checked

```solidity
// Blacklist patterns
0xfe575a87 - isBlacklisted(address)
0x0ecb93c0 - isBlackListed(address)
0x59bf1abe - blacklist(address)
0xf9f92be4 - addBlackList(address)

// Core ERC20
0xa9059cbb - transfer(address,uint256)
0x23b872dd - transferFrom(address,address,uint256)
0x095ea7b3 - approve(address,uint256)

// Privilege functions
0x40c10f19 - mint(address,uint256)
0x42966c68 - burn(uint256)

// Ownership
0x8da5cb5b - owner()
```

### Opcodes Monitored

- `0xF4` - DELEGATECALL (proxy/upgrade mechanism)
- `0xFF` - SELFDESTRUCT (contract can be destroyed)

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Test thoroughly
4. Submit a pull request

### Ideas for Improvements:

- [ ] Add more honeypot patterns
- [ ] Liquidity pool checks
- [ ] Multi-chain support
- [ ] JSON output format
- [ ] Batch analysis mode
- [ ] Tax calculation estimates

---

## 📄 License

MIT License - See LICENSE file for details

---

## ⚖️ Disclaimer

**NOT FINANCIAL ADVICE**

This tool is provided "as-is" for educational and research purposes.

- ❌ No guarantees of accuracy
- ❌ Not a substitute for due diligence
- ❌ You are responsible for your investment decisions
- ❌ Author not liable for any losses

**Always DYOR (Do Your Own Research)**

---

## 🔗 Links

- **Repository:** https://github.com/sk3yron/honeypot-detector
- **Foundry:** https://getfoundry.sh

---

## 📞 Support

Found a bug? Have a suggestion?

- Open an issue on GitHub
- Provide: token address, error message, output with `-v` flag

---

**Made with ❤️ for the PulseChain community**

*Stay safe out there! 🛡️*
