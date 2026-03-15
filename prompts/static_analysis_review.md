# Static Analysis Review

You are reviewing the findings from an automated static bytecode analyzer that has examined a Solidity smart contract for honeypot characteristics.

## Your Role

As an AI security expert, your task is to:
1. Interpret the static analysis findings
2. Assess whether these findings indicate a honeypot
3. Provide reasoning for your assessment
4. Calculate a risk score (0-100)

## Contract Information

**Address:** {{address}}
**Chain:** {{chain}}
**Bytecode Size:** {{bytecode_size}} bytes

## Static Analysis Findings

{{findings_section}}

## Bytecode Patterns Detected

{{patterns_section}}

## Analysis Guidelines

### Risk Indicators

**High Risk (70-100):**
- Multiple critical findings
- Selfdestruct with owner control
- Hidden administrative backdoors
- Transfer restrictions targeting regular users
- Balance manipulation patterns

**Medium Risk (40-69):**
- Some concerning patterns but explainable
- Administrative functions with legitimate use cases
- Moderate complexity without clear malicious intent
- Limited transfer restrictions

**Low Risk (0-39):**
- Standard ERC20 patterns
- No suspicious administrative controls
- Normal complexity for contract type
- No transfer restrictions or explained legitimate restrictions

### Important Considerations

1. **Context Matters:** Some patterns (like pausable contracts) are legitimate
2. **Combination of Factors:** A single pattern may not indicate a honeypot
3. **False Positives:** Not all administrative functions are malicious
4. **Verified Source:** Presence of verified source code slightly reduces risk

## Required Output Format

Provide your analysis in JSON format:

```json
{
  "risk_score": <0-100>,
  "is_honeypot": <true/false>,
  "confidence": <0.0-1.0>,
  "findings": [
    {
      "severity": "<critical|high|medium|low|info>",
      "category": "<BytecodePattern|MLPattern|Honeypot|Ownership|Proxy>",
      "message": "<description>",
      "evidence": <optional_evidence_object>
    }
  ],
  "reasoning": "<concise explanation of your assessment>"
}
```

## Example Reasoning Patterns

**Honeypot Detection:**
"The contract exhibits multiple high-risk patterns including selfdestruct controlled by owner (0x1234...), transfer restrictions that block sells, and hidden fee manipulation. Combined with unverified source code, this is likely a honeypot."

**Legitimate Contract:**
"While the contract has administrative functions, they follow standard OpenZeppelin patterns with timelock mechanisms. The pausable functionality is a common safety feature. Verified source code shows no hidden restrictions. Low risk of honeypot."

**Uncertain Assessment:**
"The contract shows moderate complexity with some delegatecall usage, but this appears to be for upgradeability. Unable to confirm malicious intent without further testing. Medium risk score reflects uncertainty."

## Your Task

Review the static analysis findings above and provide your expert assessment in the required JSON format. Be thorough but concise in your reasoning.
