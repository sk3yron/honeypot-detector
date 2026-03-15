#!/bin/bash
TOKEN="0x463413c579D29c26D59a65312657DFCe30D545A1"
WPLS="0xA1077a294dDE1B09bB078844df40758a5D0f9a27"
FACTORY="0x29eA7545DEf87022BAdc76323F373EA1e707C523"

echo "Checking pool state for token $TOKEN"
echo ""

# Get pair address using cast (if available)
echo "Finding pair address..."
cast call $FACTORY "getPair(address,address)(address)" $TOKEN $WPLS --rpc-url https://rpc.pulsechain.com 2>/dev/null || echo "Cast not available"
