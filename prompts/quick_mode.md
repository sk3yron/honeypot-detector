# Quick Analysis Mode

**Budget:** $50 | **Timeout:** 5 minutes | **Goal:** Fast pattern-based detection

## Strategy for Quick Mode

This mode prioritizes **speed over depth**. Focus on well-known patterns and obvious red flags.

### Workflow

1. **Get contract bytecode** (required)
   ```
   get_contract_info(address)
   ```

2. **Try to get source code** (if quick)
   ```
   get_source_code(address, chain)
   ```
   - If available → great!
   - If not → no problem, continue with bytecode

3. **Run static analysis** (required)
   ```
   analyze_bytecode_patterns(bytecode)
   ```
   - This gives you quick pattern detection
   - Look for critical findings

4. **Make decision based on patterns**
   - Critical findings (blacklist, broken ERC20) → HONEYPOT
   - No critical findings → SAFE (with medium confidence)
   - Unclear → Report low confidence

### What to SKIP in Quick Mode

- ❌ Don't test multiple holders (too slow)
- ❌ Don't write exploit contracts
- ❌ Don't do deep bytecode disassembly
- ❌ Don't simulate complex scenarios

### What to FOCUS on in Quick Mode

- ✅ Known malicious function selectors
- ✅ Broken ERC20 implementation
- ✅ Obvious bytecode red flags
- ✅ Contract size anomalies

### Decision Matrix

| Pattern Found | Verdict | Confidence |
|---------------|---------|------------|
| Blacklist function | HONEYPOT | 0.90 |
| Broken ERC20 (no transferFrom) | HONEYPOT | 0.95 |
| Missing transfer() | HONEYPOT | 0.95 |
| Pause function + unverified | UNCERTAIN | 0.50 |
| All checks pass | SAFE | 0.70 |

### Example Quick Analysis

```json
{
  "is_honeypot": true,
  "confidence": 0.90,
  "risk_score": 95,
  "findings": [
    {
      "severity": "Critical",
      "category": "BytecodePattern",
      "message": "Blacklist function detected: isBlacklisted(address)",
      "evidence": {"selector": "0xfe575a87"}
    }
  ],
  "reasoning": "Quick scan detected blacklist function selector in bytecode. Contract is not verified. This is a strong indicator of honeypot behavior.",
  "recommendations": "Avoid this token. Blacklist mechanism detected."
}
```

## Remember

- **Speed is key** - Don't overthink
- **Known patterns only** - Stick to the checklist
- **Be clear about limitations** - If uncertain, say so
- **Low confidence is OK** - Better than wrong answer
