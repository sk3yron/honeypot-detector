import { ethers } from 'ethers';

const token = '0xaAE18Cd46C45d343BbA1eab46716B4D69d799734';
const provider = new ethers.JsonRpcProvider('https://rpc.pulsechain.com');

console.log('📊 Detailed Token Analysis');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
console.log(`Token: ${token}\n`);

// Get bytecode
const bytecode = await provider.getCode(token);
console.log(`Bytecode: ${bytecode.length} bytes\n`);

// Check verified source
const explorerUrl = `https://api.scan.pulsechain.com/api?module=contract&action=getsourcecode&address=${token}`;
const response = await fetch(explorerUrl);
const data = await response.json();

if (data.result && data.result[0]) {
  const result = data.result[0];
  console.log('Contract Information:');
  console.log(`  Name: ${result.ContractName || 'Not Available'}`);
  console.log(`  Verified: ${result.SourceCode ? 'Yes ✓' : 'No ✗'}`);
  if (result.SourceCode && result.SourceCode.length > 0) {
    console.log(`  Compiler: ${result.CompilerVersion}`);
    console.log(`  Optimization: ${result.OptimizationUsed === '1' ? 'Yes' : 'No'}`);
    console.log(`  Runs: ${result.Runs}`);
  }
  console.log();
}

// Pattern analysis
console.log('Security Pattern Analysis:');
const patterns = {
  'ERC20 transfer()': bytecode.includes('a9059cbb'),
  'ERC20 approve()': bytecode.includes('095ea7b3'),
  'ERC20 balanceOf()': bytecode.includes('70a08231'),
  'Blacklist/Ban': bytecode.toLowerCase().includes('626c61636b') || bytecode.includes('62616e'),
  'Pause mechanism': bytecode.toLowerCase().includes('706175736') || bytecode.includes('5061757365'),
  'Mint function': bytecode.toLowerCase().includes('6d696e74'),
  'Burn function': bytecode.toLowerCase().includes('6275726e'),
  'Owner controls': bytecode.toLowerCase().includes('6f776e6572'),
  'DELEGATECALL': bytecode.includes('f4'),
};

for (const [name, found] of Object.entries(patterns)) {
  console.log(`  ${found ? '✅' : '❌'} ${name}`);
}

// Try to get token info
console.log('\nToken Details:');
try {
  const contract = new ethers.Contract(token, [
    'function name() view returns (string)',
    'function symbol() view returns (string)',
    'function decimals() view returns (uint8)',
    'function totalSupply() view returns (uint256)',
  ], provider);
  
  const [name, symbol, decimals, totalSupply] = await Promise.all([
    contract.name().catch(() => 'Unknown'),
    contract.symbol().catch(() => 'Unknown'),
    contract.decimals().catch(() => 18),
    contract.totalSupply().catch(() => BigInt(0)),
  ]);
  
  console.log(`  Name: ${name}`);
  console.log(`  Symbol: ${symbol}`);
  console.log(`  Decimals: ${decimals}`);
  console.log(`  Total Supply: ${ethers.formatUnits(totalSupply, decimals)}`);
} catch (e) {
  console.log('  Could not fetch token details');
}

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
