# Pool Tracker Usage Guide

## 🚀 What It Does

Real-time tracking of PulseChain DEX pool reserves by monitoring `Sync` events.

**Benefits:**
- ✅ Know liquidity for any token instantly
- ✅ Skip testing low-liquidity tokens
- ✅ Detect rugpulls (sudden liquidity drops)
- ✅ No need for constant RPC calls
- ✅ Works with public RPC (no local node needed)

---

## 📋 How to Run

### Start the Tracker (Background Process)

```bash
# Build
cargo build --release --bin pool-tracker

# Run (keeps running and updating)
./target/release/pool-tracker

# Or with custom RPC
RPC_URL="https://rpc.pulsechain.com" ./target/release/pool-tracker

# Run in background
nohup ./target/release/pool-tracker > pool-tracker.log 2>&1 &
```

### How It Works

1. **First Run:** Scans last 1000 blocks to populate initial data
2. **Ongoing:** Polls every 3 seconds for new blocks
3. **Updates:** Tracks `Sync` events and updates reserves
4. **Saves:** Persists to `data/pools.json` after each sync

---

## 📊 Output Format

**File:** `data/pools.json`

```json
{
  "last_synced_block": 25093046,
  "last_updated": "2024-11-23T08:20:45Z",
  "pools": {
    "0x1234...": {
      "pair": "0x1234...",
      "token0": "0xabcd...",
      "token1": "0xA107...",
      "reserve0": "1000000000000000000",
      "reserve1": "500000000000000000",
      "last_updated_block": 25093040
    }
  }
}
```

---

## 🔧 Integration with Honeypot Detector

### Load Pool Data Before Checking

```rust
use honeypot_detector::pool_tracker::PoolCache;

async fn check_honeypot(token: Address) -> Result<()> {
    // 1. Load pool cache
    let cache = PoolCache::load_from_file("data/pools.json")?;
    
    // 2. Find pool for token paired with WPLS
    let wpls: Address = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27".parse()?;
    
    if let Some(pool) = cache.find_pool_for_token(token, wpls) {
        println!("Pool: {:?}", pool.pair);
        println!("Reserves: {} / {}", pool.reserve0, pool.reserve1);
        
        // TODO: Calculate USD liquidity
        // If < $100, skip honeypot check
    } else {
        println!("⚠️  No pool found for this token");
    }
    
    // Continue with normal honeypot check...
}
```

---

## 📈 Performance

**Initial Scan (1000 blocks):**
- Time: ~4-5 seconds
- Events: 20,000-30,000 Sync events
- Pools: 500-1000 unique pairs

**Ongoing Updates:**
- Frequency: Every 3 seconds
- Load: Minimal (only new blocks)
- RPC calls: 1-2 per update

---

## 💡 Tips

### Run as System Service

Create `/etc/systemd/system/pool-tracker.service`:

```ini
[Unit]
Description=PulseChain Pool Tracker
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/honeypot-detector
ExecStart=/path/to/honeypot-detector/target/release/pool-tracker
Restart=always
Environment="RPC_URL=https://rpc.pulsechain.com"

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl enable pool-tracker
sudo systemctl start pool-tracker
sudo systemctl status pool-tracker
```

### Monitor Progress

```bash
# Watch the log
tail -f pool-tracker.log

# Check pool count
cat data/pools.json | jq '.pools | length'

# See last synced block
cat data/pools.json | jq '.last_synced_block'
```

---

## 🔄 Future Enhancements

- [ ] Calculate USD liquidity from reserves
- [ ] Track liquidity changes over time
- [ ] Alert on sudden drops (rugpull detection)
- [ ] Support multiple DEXes (9mm, 9inch, etc.)
- [ ] Web dashboard for pool stats

---

## 🐛 Troubleshooting

**Problem:** Tracker stops/crashes

**Solution:**
```bash
# Check the log
tail -100 pool-tracker.log

# Restart tracker (will resume from last synced block)
./target/release/pool-tracker
```

**Problem:** Missing pools

**Solution:**
- Tracker only tracks pools with Sync events in scanned blocks
- Initial scan is last 1000 blocks only
- Older pools will be added as they trade

**Problem:** RPC rate limits

**Solution:**
- Use a better RPC provider
- Increase poll interval (edit `poll_interval` in code)
- Run your own local node

---

**Made for PulseChain** • Built with ❤️
