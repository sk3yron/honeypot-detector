# Deep Analysis Mode

**Budget:** $200 | **Timeout:** 30 minutes | **Goal:** Exhaustive exploitation attempts

## Strategy for Deep Mode

This mode performs **SCONE-bench style analysis** - attempt to actually exploit the contract like a real attacker would. Use this for high-stakes analysis or when other modes are uncertain.

### Comprehensive Workflow

#### Phase 1: Full Information Gathering (5 minutes)

1. Get all contract information
2. Fetch source code (try multiple explorers if needed)
3. Run complete static analysis
4. Analyze storage layout
5. Check admin functions and ownership

#### Phase 2: Multiple Test Vectors (10 minutes)

Test ALL available methods:

1. **Approved holder testing** (5-10 holders)
   - Find holders across entire history
   - Test various holder sizes
   - Document all failure types

2. **Transfer simulation**
   - Test with various amounts
   - Test edge cases (max uint, zero, dust)
   - Check for overflow conditions

3. **DEX interaction testing**
   - Test on multiple DEXs (PulseX V1, V2, Piteas)
   - Simulate buy and sell
   - Check for routing issues

#### Phase 3: Exploit Development (15 minutes)

**Only in Deep Mode:**

If vulnerability suspected, attempt to create proof-of-concept:

1. **Analyze the attack vector**
   - U112 overflow
   - Reentrancy
   - Access control bypass
   - Storage manipulation

2. **Write exploit logic**
   - Use available tools
   - Document attack steps
   - Calculate potential profit

3. **Test exploit** (if tools available)
   - Deploy on local fork
   - Execute attack
   - Verify results

### Attack Vectors to Test

| Vector | Description | How to Test |
|--------|-------------|-------------|
| U112 Overflow | Balance > 2^112 causes overflow | Large transfer simulation |
| Blacklist | Specific addresses blocked | Test multiple holders |
| Broken ERC20 | Missing critical functions | Static analysis |
| Hidden Owner | Owner can block transfers | Check storage + permissions |
| Reentrancy | Recursive calls drain funds | Source code review |
| Flash Loan Attack | Exploit via flash loan | Complex simulation |

### Thoroughness Checklist

- [ ] Contract bytecode analyzed
- [ ] Source code reviewed (if available)
- [ ] 10+ holders tested
- [ ] Multiple DEXs tested
- [ ] Edge cases checked
- [ ] Storage layout analyzed
- [ ] Admin functions documented
- [ ] Ownership status verified
- [ ] Historical transactions reviewed
- [ ] Exploit attempted (if applicable)

### Example Deep Analysis

**Scenario: Novel honeypot mechanism**

```json
{
  "is_honeypot": true,
  "confidence": 0.97,
  "risk_score": 98,
  "findings": [
    {
      "severity": "Critical",
      "category": "Honeypot",
      "message": "Novel honeypot: Storage-based balance manipulation",
      "evidence": {
        "mechanism": "Contract stores balances in two separate mappings. Buys update mapping A, sells check mapping B. Mapping B never gets updated.",
        "storage_slots": ["0x05", "0x06"],
        "exploit_path": "detailed_in_reasoning"
      }
    },
    {
      "severity": "Critical",
      "category": "Simulation",
      "message": "10/10 tested holders cannot sell",
      "evidence": {
        "tested": 10,
        "successful": 0,
        "holders_tested": ["0x123...", "0x456..."]
      }
    }
  ],
  "reasoning": "Deep analysis uncovered a novel honeypot mechanism:\n\n1. Initial bytecode analysis showed unusual storage access patterns\n2. Source code is not verified, proceeding with bytecode disassembly\n3. Discovered two separate balance mappings at storage slots 0x05 and 0x06\n4. Tracing transaction flow:\n   - _transfer() for buys updates balanceOf mapping (slot 0x05)\n   - _transfer() for sells checks _sellBalances mapping (slot 0x06)  \n   - Slot 0x06 is NEVER updated\n5. Tested 10 approved holders with confirmed balances - ALL sells failed\n6. Failure reason: Balance check reverts because _sellBalances is always zero\n\nThis is a sophisticated honeypot using storage manipulation to separate buy and sell balance tracking.",
  "recommendations": "CRITICAL: DO NOT BUY. This is an advanced honeypot with a novel mechanism. The contract intentionally tracks balances in separate storage locations for buys vs sells, ensuring sells always fail.",
  "exploit_description": "Attack vector: No profitable exploit exists. This is a pure honeypot designed to trap funds. Only the contract creator can extract value by repeatedly deploying similar tokens.",
  "technical_details": {
    "buy_balance_slot": "0x05",
    "sell_balance_slot": "0x06",
    "update_function": "_updateBuyBalance",
    "check_function": "_checkSellBalance",
    "owner": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "is_renounced": false
  }
}
```

## Budget Management

Deep mode uses extended thinking and thorough testing:

- **Phase 1 (Info Gathering):** ~$30
- **Phase 2 (Multiple Tests):** ~$60
- **Phase 3 (Exploit Development):** ~$80
- **Extended Thinking:** ~$20
- **Buffer:** ~$10

**Total:** $180-200, using full budget

## Important Notes

- **Time intensive** - Don't use for routine checks
- **High accuracy** - Best for confirming suspicions
- **Detailed reports** - Provide technical evidence
- **Exploit ethics** - Document but don't execute on mainnet
- **Novel patterns** - Can discover new honeypot types

## When to Use Deep Mode

✅ **Use Deep Mode when:**
- High-value token (>$100k liquidity)
- Conflicting analyzer results
- Suspected novel honeypot mechanism
- Legal/audit requirements
- Research purposes

❌ **Don't use Deep Mode for:**
- Routine token checks
- Obvious honeypots
- Batch analysis
- Time-sensitive decisions
- Low-value tokens

## Remember

- **Thoroughness over speed** - Take your time
- **Document everything** - Detailed findings matter
- **Think like an attacker** - But act ethically
- **Novel mechanisms** - Look for new patterns
- **High confidence** - Your verdict should be definitive
