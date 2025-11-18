# PulseChain Honeypot Detector

Fast and reliable honeypot detection for PulseChain tokens.

---

## 🚀 Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/check-honeypot <TOKEN_ADDRESS>
```

---

## 📋 Usage

```bash
# Basic check
./target/release/check-honeypot 0xYourTokenAddress

# Custom RPC
./target/release/check-honeypot --rpc https://rpc.pulsechain.com 0xYourTokenAddress

# Using environment variable
export RPC_URL="https://rpc.pulsechain.com"
./target/release/check-honeypot 0xYourTokenAddress
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

1. **Static Analysis** - Scans bytecode for malicious patterns
2. **Holder Simulation** - Tests actual swap execution with real holders
3. **Multi-Router Testing** - Tests PulseX V1, V2, and Piteas
4. **Historical Scanning** - Finds holders across entire token history

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

```bash
# Set RPC endpoint
export RPC_URL="https://your-rpc.com"

# Enable debug logging
export RUST_LOG="honeypot_detector=debug"
```

---

## 🛠️ Development

```bash
# Run tests
cargo test

# Run examples
cargo run --example test_approved_holder
cargo run --example test_swap
```

---

## 🔒 Disclaimer

This tool is for **research and educational purposes only**.

- Always do your own research
- Test with small amounts first
- No guarantees - use at your own risk

---

## 📄 License

MIT

---

**Made for PulseChain** • Supports PulseX V1, V2, Piteas
