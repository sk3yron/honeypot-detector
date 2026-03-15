#!/usr/bin/env node
/**
 * Honeypot Detector MCP Server
 * 
 * Provides tools for Claude to analyze smart contracts for honeypot detection.
 * Tools include contract info fetching, source code retrieval, bytecode analysis,
 * transfer simulation, and approved holder testing.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ethers } from "ethers";
import axios from "axios";

// Environment configuration
const RPC_URL = process.env.PULSECHAIN_RPC || "https://rpc.pulsechain.com";
const BSCSCAN_API_KEY = process.env.BSCSCAN_API_KEY || "";
const PULSESCAN_API_KEY = process.env.PULSESCAN_API_KEY || "";

// Initialize ethers provider
const provider = new ethers.JsonRpcProvider(RPC_URL);

/**
 * Tool 1: Get Contract Info
 * Fetches basic contract information including bytecode, size, and chain details
 */
async function getContractInfo(address: string): Promise<any> {
  try {
    const checksumAddress = ethers.getAddress(address);
    
    // Get bytecode
    const bytecode = await provider.getCode(checksumAddress);
    
    // Get network info
    const network = await provider.getNetwork();
    
    // Check if it's a contract
    const isContract = bytecode !== "0x";
    
    return {
      address: checksumAddress,
      bytecode: bytecode,
      bytecode_size: bytecode.length / 2 - 1, // Convert hex length to bytes
      is_contract: isContract,
      chain_id: network.chainId.toString(),
      chain_name: network.name || "PulseChain",
      rpc_url: RPC_URL,
    };
  } catch (error: any) {
    return {
      error: `Failed to get contract info: ${error.message}`,
      address: address,
    };
  }
}

/**
 * Tool 2: Get Source Code
 * Attempts to fetch verified source code from block explorers
 */
async function getSourceCode(address: string, chain: string = "pulsechain"): Promise<any> {
  try {
    const checksumAddress = ethers.getAddress(address);
    
    let apiUrl = "";
    let apiKey = "";
    
    // Determine API endpoint based on chain
    if (chain.toLowerCase() === "bsc" || chain === "56") {
      apiUrl = "https://api.bscscan.com/api";
      apiKey = BSCSCAN_API_KEY;
    } else if (chain.toLowerCase() === "ethereum" || chain === "1") {
      apiUrl = "https://api.etherscan.io/api";
      apiKey = process.env.ETHERSCAN_API_KEY || "";
    } else {
      // PulseChain (369) or default
      apiUrl = "https://api.scan.pulsechain.com/api";
      apiKey = PULSESCAN_API_KEY;
    }
    
    // Make API request
    const response = await axios.get(apiUrl, {
      params: {
        module: "contract",
        action: "getsourcecode",
        address: checksumAddress,
        apikey: apiKey,
      },
      timeout: 10000,
    });
    
    if (response.data.status === "1" && response.data.result && response.data.result[0]) {
      const result = response.data.result[0];
      
      // Check if source code is available
      if (result.SourceCode && result.SourceCode !== "") {
        return {
          verified: true,
          source_code: result.SourceCode,
          contract_name: result.ContractName,
          compiler_version: result.CompilerVersion,
          optimization_used: result.OptimizationUsed === "1",
          runs: parseInt(result.Runs || "200"),
          abi: result.ABI,
          constructor_arguments: result.ConstructorArguments,
        };
      } else {
        return {
          verified: false,
          message: "Contract source code not verified on block explorer",
          address: checksumAddress,
        };
      }
    } else {
      return {
        verified: false,
        message: "Unable to fetch source code from block explorer",
        address: checksumAddress,
      };
    }
  } catch (error: any) {
    return {
      error: `Failed to get source code: ${error.message}`,
      verified: false,
      address: address,
    };
  }
}

/**
 * Tool 3: Analyze Bytecode Patterns
 * This is a placeholder that will call the Rust static analyzer
 * For now, it returns basic pattern detection
 */
async function analyzeBytecodePatterns(bytecode: string): Promise<any> {
  try {
    const findings: any[] = [];
    const bytecodeUpper = bytecode.toUpperCase();
    
    // Check for common honeypot patterns
    const patterns = {
      blacklist_functions: [
        { selector: "FE575A87", name: "isBlacklisted(address)" },
        { selector: "0ECB93C0", name: "isBlackListed(address)" },
        { selector: "59BF1ABE", name: "blacklist(address)" },
        { selector: "F9F92BE4", name: "addBlackList(address)" },
        { selector: "E4997DC5", name: "removeBlackList(address)" },
      ],
      erc20_functions: [
        { selector: "A9059CBB", name: "transfer(address,uint256)" },
        { selector: "23B872DD", name: "transferFrom(address,address,uint256)" },
        { selector: "095EA7B3", name: "approve(address,uint256)" },
      ],
      admin_functions: [
        { selector: "40C10F19", name: "mint(address,uint256)" },
        { selector: "42966C68", name: "burn(uint256)" },
        { selector: "8456CB59", name: "pause()" },
        { selector: "3F4BA83A", name: "unpause()" },
      ],
    };
    
    // Check for blacklist functions
    for (const pattern of patterns.blacklist_functions) {
      if (bytecodeUpper.includes(pattern.selector)) {
        findings.push({
          severity: "Critical",
          category: "BytecodePattern",
          message: `Blacklist function detected: ${pattern.name}`,
          selector: pattern.selector,
        });
      }
    }
    
    // Check for ERC20 compliance
    const hasTransfer = bytecodeUpper.includes("A9059CBB");
    const hasTransferFrom = bytecodeUpper.includes("23B872DD");
    const hasApprove = bytecodeUpper.includes("095EA7B3");
    
    if (!hasTransfer) {
      findings.push({
        severity: "Critical",
        category: "BytecodePattern",
        message: "Missing transfer() function - NOT ERC20 compliant",
      });
    }
    
    if (hasApprove && !hasTransferFrom) {
      findings.push({
        severity: "Critical",
        category: "Honeypot",
        message: "Broken ERC20: approve() exists but NO transferFrom()",
      });
    }
    
    // Check for admin functions
    for (const pattern of patterns.admin_functions) {
      if (bytecodeUpper.includes(pattern.selector)) {
        findings.push({
          severity: "Medium",
          category: "BytecodePattern",
          message: `Admin function detected: ${pattern.name}`,
          selector: pattern.selector,
        });
      }
    }
    
    // Contract size analysis
    const sizeBytes = bytecode.length / 2 - 1;
    if (sizeBytes < 100) {
      findings.push({
        severity: "High",
        category: "BytecodePattern",
        message: `Suspiciously small contract (${sizeBytes} bytes)`,
      });
    } else if (sizeBytes > 24576) {
      findings.push({
        severity: "Critical",
        category: "BytecodePattern",
        message: `Contract exceeds maximum size (${sizeBytes} bytes > 24576 limit)`,
      });
    }
    
    return {
      bytecode_size: sizeBytes,
      findings: findings,
      has_transfer: hasTransfer,
      has_transferFrom: hasTransferFrom,
      has_approve: hasApprove,
      erc20_compliant: hasTransfer && hasTransferFrom && hasApprove,
    };
  } catch (error: any) {
    return {
      error: `Failed to analyze bytecode: ${error.message}`,
    };
  }
}

/**
 * Tool 4: Simulate Transfer
 * This is a placeholder for REVM simulation
 * Will need to call Rust code for actual simulation
 */
async function simulateTransfer(
  token: string,
  from: string,
  to: string,
  amount: string
): Promise<any> {
  try {
    const checksumToken = ethers.getAddress(token);
    const checksumFrom = ethers.getAddress(from);
    const checksumTo = ethers.getAddress(to);
    
    // For MVP, we'll use eth_call to test if the function exists
    // Full REVM simulation will be done in Rust
    
    // Build transfer calldata
    const iface = new ethers.Interface([
      "function transfer(address to, uint256 amount) returns (bool)",
    ]);
    const calldata = iface.encodeFunctionData("transfer", [checksumTo, amount]);
    
    try {
      // Try to call the transfer function
      const result = await provider.call({
        to: checksumToken,
        from: checksumFrom,
        data: calldata,
      });
      
      return {
        simulation: "basic_call_test",
        success: true,
        result: result,
        message: "Transfer function callable (basic test only, full simulation in Rust)",
        note: "This is a lightweight check. Full REVM simulation with balance injection is done in Rust.",
      };
    } catch (callError: any) {
      return {
        simulation: "basic_call_test",
        success: false,
        error: callError.message,
        revert_reason: callError.data || "Unknown",
        message: "Transfer function reverted (basic test only)",
      };
    }
  } catch (error: any) {
    return {
      error: `Failed to simulate transfer: ${error.message}`,
    };
  }
}

/**
 * Tool 5: Test Approved Holder Sell
 * Tests if an approved holder can sell tokens using eth_estimateGas
 */
async function testApprovedHolderSell(
  token: string,
  holder: string,
  router: string = "0x98bf93ebf5c380C0e6Ae8e192A7e2AE08edAcc02" // PulseX V2 Router
): Promise<any> {
  try {
    const checksumToken = ethers.getAddress(token);
    const checksumHolder = ethers.getAddress(holder);
    const checksumRouter = ethers.getAddress(router);
    
    // Get holder's token balance
    const tokenContract = new ethers.Contract(
      checksumToken,
      ["function balanceOf(address) view returns (uint256)"],
      provider
    );
    
    const balance = await tokenContract.balanceOf(checksumHolder);
    
    if (balance === 0n) {
      return {
        can_sell: false,
        reason: "InsufficientBalance",
        balance: "0",
        message: "Holder has zero balance",
      };
    }
    
    // Get allowance
    const allowanceContract = new ethers.Contract(
      checksumToken,
      ["function allowance(address,address) view returns (uint256)"],
      provider
    );
    
    const allowance = await allowanceContract.allowance(checksumHolder, checksumRouter);
    
    if (allowance === 0n) {
      return {
        can_sell: false,
        reason: "NeedsApproval",
        balance: balance.toString(),
        allowance: "0",
        message: "Holder needs to approve router",
      };
    }
    
    // Build swap calldata
    const routerInterface = new ethers.Interface([
      "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
    ]);
    
    const WPLS = "0xA1077a294dDE1B09bB078844df40758a5D0f9a27"; // Wrapped PLS
    const amountToSell = balance / 10n; // Try to sell 10% of balance
    const path = [checksumToken, WPLS];
    const deadline = Math.floor(Date.now() / 1000) + 300; // 5 min deadline
    
    const swapCalldata = routerInterface.encodeFunctionData(
      "swapExactTokensForETHSupportingFeeOnTransferTokens",
      [amountToSell, 0, path, checksumHolder, deadline]
    );
    
    try {
      // Estimate gas for the swap
      const gasEstimate = await provider.estimateGas({
        from: checksumHolder,
        to: checksumRouter,
        data: swapCalldata,
      });
      
      return {
        can_sell: true,
        balance: balance.toString(),
        allowance: allowance.toString(),
        amount_to_sell: amountToSell.toString(),
        gas_estimate: gasEstimate.toString(),
        message: "Holder can successfully sell tokens",
      };
    } catch (estimateError: any) {
      // Parse revert reason
      let failureType = "Unknown";
      const errorMsg = estimateError.message.toLowerCase();
      
      if (errorMsg.includes("insufficient") && errorMsg.includes("liquidity")) {
        failureType = "InsufficientLiquidity";
      } else if (errorMsg.includes("overflow") || errorMsg.includes("arithmetic")) {
        failureType = "MathOverflow";
      } else if (errorMsg.includes("transfer") && errorMsg.includes("blocked")) {
        failureType = "TransferBlocked";
      }
      
      return {
        can_sell: false,
        reason: failureType,
        balance: balance.toString(),
        allowance: allowance.toString(),
        error: estimateError.message,
        message: "Sell transaction would fail",
      };
    }
  } catch (error: any) {
    return {
      error: `Failed to test holder sell: ${error.message}`,
      can_sell: false,
    };
  }
}

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "get_contract_info",
    description:
      "Fetches basic contract information including bytecode, size, and chain details. Use this first to get bytecode for analysis.",
    inputSchema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "The contract address (0x...)",
        },
      },
      required: ["address"],
    },
  },
  {
    name: "get_source_code",
    description:
      "Attempts to fetch verified source code from block explorers (PulseScan, BscScan, Etherscan). Returns verified status and source code if available.",
    inputSchema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "The contract address (0x...)",
        },
        chain: {
          type: "string",
          description: 'Chain name: "pulsechain" (default), "bsc", or "ethereum"',
          default: "pulsechain",
        },
      },
      required: ["address"],
    },
  },
  {
    name: "analyze_bytecode_patterns",
    description:
      "Analyzes bytecode for known honeypot patterns including blacklist functions, broken ERC20 implementation, admin functions, and suspicious contract size.",
    inputSchema: {
      type: "object",
      properties: {
        bytecode: {
          type: "string",
          description: "The contract bytecode (0x...)",
        },
      },
      required: ["bytecode"],
    },
  },
  {
    name: "simulate_transfer",
    description:
      "Tests if a transfer function can be called (basic check). For full REVM simulation with balance injection, the Rust analyzer will be used.",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "string",
          description: "Token contract address",
        },
        from: {
          type: "string",
          description: "Sender address",
        },
        to: {
          type: "string",
          description: "Recipient address",
        },
        amount: {
          type: "string",
          description: "Amount to transfer (in wei)",
        },
      },
      required: ["token", "from", "to", "amount"],
    },
  },
  {
    name: "test_approved_holder_sell",
    description:
      "Tests if a real token holder can sell their tokens using eth_estimateGas. This is the most reliable RPC-only honeypot detection method.",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "string",
          description: "Token contract address",
        },
        holder: {
          type: "string",
          description: "Holder address to test",
        },
        router: {
          type: "string",
          description: "DEX router address (defaults to PulseX V2)",
          default: "0x98bf93ebf5c380C0e6Ae8e192A7e2AE08edAcc02",
        },
      },
      required: ["token", "holder"],
    },
  },
];

// Create MCP server
const server = new Server(
  {
    name: "honeypot-detector-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list_tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOLS,
  };
});

// Handle call_tool request
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (!args) {
    throw new Error("Missing arguments");
  }

  try {
    let result: any;

    switch (name) {
      case "get_contract_info":
        result = await getContractInfo(args.address as string);
        break;

      case "get_source_code":
        result = await getSourceCode(
          args.address as string,
          (args.chain as string) || "pulsechain"
        );
        break;

      case "analyze_bytecode_patterns":
        result = await analyzeBytecodePatterns(args.bytecode as string);
        break;

      case "simulate_transfer":
        result = await simulateTransfer(
          args.token as string,
          args.from as string,
          args.to as string,
          args.amount as string
        );
        break;

      case "test_approved_holder_sell":
        result = await testApprovedHolderSell(
          args.token as string,
          args.holder as string,
          (args.router as string) || "0x98bf93ebf5c380C0e6Ae8e192A7e2AE08edAcc02"
        );
        break;

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: `Tool execution failed: ${error.message}`,
              tool: name,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Honeypot Detector MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
