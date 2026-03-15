# Hybrid Analysis Mode (DEFAULT)

**Budget:** $100 | **Timeout:** 15 minutes | **Goal:** Balance speed and thoroughness

## Strategy for Hybrid Mode

This is the **recommended default mode**. It combines fast pattern detection with selective deeper testing when needed.

### Adaptive Workflow

#### Phase 1: Quick Assessment (2-3 minutes)

1. Get contract info and bytecode
2. Try to get source code
3. Run static bytecode analysis
4. Make initial assessment

#### Phase 2: Decide Next Steps

**If Phase 1 shows CLEAR HONEYPOT:**
- Confidence ≥ 0.85
- Critical findings (blacklist, broken ERC20)
- ✅ STOP HERE - Report honeypot

**If Phase 1 shows CLEARLY SAFE:**
- Confidence ≥ 0.80
- All checks pass
- Standard ERC20 implementation
- ✅ STOP HERE - Report safe

**If Phase 1 is UNCERTAIN:**
- Confidence < 0.75
- Conflicting signals
- ⚠️ ESCALATE to Phase 3

#### Phase 3: Deeper Testing (10-12 minutes)

When uncertain, run additional tests:

1. **Test approved holder sells** (CRITICAL)
   ```
   test_approved_holder_sell(token, holder, router)
   ```
   - Find 3-5 holders with balance
   - Test if they can sell
   - This catches 85-90% of remaining honeypots

2. **Simulate transfer** (if holder tests inconclusive)
   ```
   simulate_transfer(token, from, to, amount)
   ```
   - Basic execution test
   - Check for reverts

3. **Source code deep dive** (if available)
   - Review transfer restrictions
   - Check for hidden conditions
   - Analyze modifiers

### Decision Tree

```
Start
  ├─> Critical Pattern Found? ──YES──> HONEYPOT (0.90 confidence)
  └─> NO
       ├─> All Checks Pass? ──YES──> SAFE (0.80 confidence)  
       └─> NO (Uncertain)
            ├─> Test Holders
            │    ├─> All Can Sell ──> SAFE (0.85 confidence)
            │    ├─> None Can Sell ──> HONEYPOT (0.90 confidence)
            │    └─> Mixed Results ──> CAUTION (0.60 confidence)
            └─> Still Uncertain ──> Report Low Confidence
```

### When to Use Each Tool

| Tool | Always | If Uncertain | Notes |
|------|--------|--------------|-------|
| get_contract_info | ✅ | - | Required |
| get_source_code | ✅ | - | Quick check |
| analyze_bytecode_patterns | ✅ | - | Fast patterns |
| test_approved_holder_sell | ❌ | ✅ | Only if uncertain |
| simulate_transfer | ❌ | ✅ | Backup test |

### Example Hybrid Analysis

**Scenario: Uncertain from static analysis**

```json
{
  "is_honeypot": true,
  "confidence": 0.88,
  "risk_score": 90,
  "findings": [
    {
      "severity": "Medium",
      "category": "BytecodePattern",
      "message": "Pausable contract detected",
      "evidence": {"selector": "0x8456cb59"}
    },
    {
      "severity": "Critical",
      "category": "Simulation",
      "message": "Approved holder sell test FAILED - 0/5 holders can sell",
      "evidence": {
        "tested_holders": 5,
        "successful": 0,
        "failure_type": "MathOverflow"
      }
    }
  ],
  "reasoning": "Initial bytecode scan showed pausable functionality which could be legitimate. However, testing 5 approved holders revealed that NONE can successfully sell their tokens. All sells failed with MathOverflow errors, indicating U112 overflow honeypot trap. High confidence honeypot.",
  "recommendations": "DO NOT BUY. This is a confirmed honeypot - real holders cannot sell."
}
```

## Budget Management

- **Phase 1 (Quick):** ~$10-15 (lightweight operations)
- **Phase 2 (Decision):** ~$5 (analysis/reasoning)
- **Phase 3 (Deep):** ~$30-50 (holder tests + simulation)
- **Buffer:** ~$30 for complex cases

**Total:** Usually $45-80, well within $100 budget

## Remember

- **Start fast** - Don't jump to deep testing immediately
- **Be adaptive** - Escalate only when needed
- **Holder tests are gold** - They're the most reliable indicator
- **Source code helps** - But most contracts aren't verified
- **Time management** - Reserve time for Phase 3 if needed
