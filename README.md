# Honeypot Detector

Simple bash script to detect honeypot tokens by attempting to buy and sell them.

**Automatically starts and stops Anvil** - just run one command!

---

## What It Does

1. Starts local Anvil node (forked from mainnet)
2. Buys tokens with WPLS
3. Tries to sell them back
4. Reports if the token is a honeypot
5. Stops Anvil automatically

---

## Installation

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Download script
wget https://github.com/sk3yron/honeypot-detector/honeypot-detector.sh
chmod +x honeypot-detector.sh
```

## Configure (choose one):


**Option A: Create `config.env` file**

```bash

RPC_URL="http://127.0.0.1:8545"
WPLS="0xA1077a294dDE1B09bB078844df40758a5D0f9a27"
ROUTER="0xDA9aBA4eACF54E0273f56dfFee6B8F1e20B23Bba"
USER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_AMOUNT="1000000000000000000000"

```

**Option B: Export variables**
```bash
export PRIVATE_KEY="0xYourPrivateKey"
export RPC_URL="https://rpc.pulsechain.com"
```

---

## Usage

```bash
./honeypot-detector.sh <TOKEN_ADDRESS>
```

**Example:**
```bash
./honeypot-detector.sh 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
```

---

## Output

### ✅ Safe Token
```
✓ NOT A HONEYPOT
Token can be bought and sold
Loss from fees/slippage: ~2%
```

### ⚠️ Honeypot
```
⚠ HONEYPOT DETECTED
Token was bought but CANNOT be sold
Type: Transfer block
```

---

## Security Warning

⚠️ **NEVER use your real wallet for testing**
- Use a test wallet with minimal funds
- Default test amount: 1000 WPLS
- You will lose this amount if it's a honeypot

---

## Troubleshooting

**Error: 'cast' not found**
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Error: PRIVATE_KEY required**
```bash
export PRIVATE_KEY="0x..."
```

**Error: Insufficient WPLS**
- Get WPLS in your test wallet
- Or lower `TEST_AMOUNT`

---

## Limitations

This tool **does NOT** detect:
- High tax tokens (>10% fees)
- Low liquidity traps
- Time-based restrictions
- Sophisticated honeypots that allow initial sells

**Always do your own research.**

---

## License

MIT - Use at your own risk.

## Disclaimer

Not financial advice. You are responsible for any losses.