#!/usr/bin/env bash
# honeypot-detector.sh - Simple honeypot detection tool

set -euo pipefail

#=============================================================================
# CONFIGURATION
#=============================================================================

[[ -f "${HONEYPOT_CONFIG:-./config.env}" ]] && source "${HONEYPOT_CONFIG:-./config.env}"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
FORK_URL="${FORK_URL:-https://rpc.pulsechain.com}"
WPLS="${WPLS:-0xA1077a294dDE1B09bB078844df40758a5D0f9a27}"
ROUTER="${ROUTER:-0xDA9aBA4eACF54E0273f56dfFee6B8F1e20B23Bba}"
USER="${USER:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
TEST_AMOUNT="${TEST_AMOUNT:-1000000000000000000000}"
USE_ANVIL="${USE_ANVIL:-true}"  # Set to false to use real RPC

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Track Anvil PID for cleanup
ANVIL_PID=""

#=============================================================================
# CLEANUP
#=============================================================================

cleanup() {
    if [[ -n "$ANVIL_PID" ]]; then
        info "Stopping Anvil (PID: $ANVIL_PID)..."
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
}

# Ensure cleanup runs on exit
trap cleanup EXIT INT TERM

#=============================================================================
# FUNCTIONS
#=============================================================================

log() { echo -e "${2:-$NC}[${1}]${NC} ${3}" >&2; }
info()  { log "INFO" "$GREEN" "$*"; }
warn()  { log "WARN" "$YELLOW" "$*"; }
error() { log "ERROR" "$RED" "$*"; }
die()   { error "$*"; exit 1; }

validate_address() {
    [[ "$1" =~ ^0x[a-fA-F0-9]{40}$ ]] || die "Invalid address: $1"
}

check_deps() {
    command -v cast >/dev/null 2>&1 || die "'cast' not found. Install Foundry: https://getfoundry.sh"
    if [[ "$USE_ANVIL" == "true" ]]; then
        command -v anvil >/dev/null 2>&1 || die "'anvil' not found. Install Foundry: https://getfoundry.sh"
    fi
}

start_anvil() {
    if [[ "$USE_ANVIL" != "true" ]]; then
        info "Using external RPC: $RPC_URL"
        return 0
    fi
    
    info "Starting Anvil (forking $FORK_URL)..."
    
    # Start Anvil in background, suppress output
    anvil --fork-url "$FORK_URL" --silent >/dev/null 2>&1 &
    ANVIL_PID=$!
    
    info "Anvil started (PID: $ANVIL_PID)"
    
    # Wait for Anvil to be ready
    info "Waiting for Anvil to initialize..."
    local retries=30
    while (( retries > 0 )); do
        if cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1; then
            info "Anvil ready!"
            return 0
        fi
        sleep 0.5
        ((retries--))
    done
    
    die "Anvil failed to start"
}

get_balance() {
    local token="$1" address="$2"
    local balance
    balance=$(cast call "$token" "balanceOf(address)" "$address" --rpc-url "$RPC_URL" 2>/dev/null) || return 1
    cast to-dec "$balance"
}

approve_token() {
    local token="$1" spender="$2" amount="$3"
    info "Approving $spender to spend tokens..."
    
    cast send "$token" "approve(address,uint256)" "$spender" "$amount" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "$RPC_URL" \
        --json >/dev/null 2>&1 || return 1
}

swap_tokens() {
    local amount="$1" path="$2"
    
    cast send "$ROUTER" \
        "swapExactTokensForTokensV2(uint256,uint256,address[],address)" \
        "$amount" "1" "$path" "$USER" \
        --private-key "$PRIVATE_KEY" \
        --rpc-url "$RPC_URL" \
        --json 2>&1
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    [[ $# -eq 0 ]] && die "Usage: $0 <token_address>"
    
    local TOKEN="$1"
    
    check_deps
    validate_address "$TOKEN"
    validate_address "$WPLS"
    validate_address "$ROUTER"
    validate_address "$USER"
    
    # Start Anvil if needed
    start_anvil
    
    echo ""
    echo -e "${YELLOW}======================================${NC}"
    echo -e "${YELLOW}   HONEYPOT DETECTION TEST${NC}"
    echo -e "${YELLOW}======================================${NC}"
    echo "Token:  $TOKEN"
    echo "Amount: $TEST_AMOUNT wei"
    echo ""
    
    # STEP 1: Initial balances
    info "Step 1/4: Checking initial balances..."
    local initial_wpls initial_token
    initial_wpls=$(get_balance "$WPLS" "$USER") || die "Failed to get WPLS balance"
    initial_token=$(get_balance "$TOKEN" "$USER" || echo "0")
    
    info "WPLS: $initial_wpls wei | Token: $initial_token wei"
    
    (( initial_wpls >= TEST_AMOUNT )) || die "Insufficient WPLS (have: $initial_wpls, need: $TEST_AMOUNT)"
    
    # STEP 2: Buy token
    info "Step 2/4: Buying token..."
    
    approve_token "$WPLS" "$ROUTER" "$TEST_AMOUNT" || die "WPLS approval failed"
    
    local buy_result
    buy_result=$(swap_tokens "$TEST_AMOUNT" "[$WPLS,$TOKEN]")
    
    if echo "$buy_result" | grep -q '"status":"0x1"'; then
        info "✓ Buy successful"
    else
        error "✗ Buy failed"
        echo "$buy_result" | grep -o '"revertReason":"[^"]*"' || echo "Unknown error"
        die "Cannot buy token"
    fi
    
    sleep 2
    
    # Check tokens received
    local new_token_balance tokens_bought
    new_token_balance=$(get_balance "$TOKEN" "$USER") || die "Failed to get new token balance"
    tokens_bought=$((new_token_balance - initial_token))
    
    info "Received: $tokens_bought tokens"
    
    (( tokens_bought > 0 )) || die "No tokens received after buy"
    
    # STEP 3: Try to sell
    info "Step 3/4: Attempting to sell token..."
    
    approve_token "$TOKEN" "$ROUTER" "$tokens_bought" || warn "Token approval might have failed"
    
    local sell_result
    sell_result=$(swap_tokens "$tokens_bought" "[$TOKEN,$WPLS]")
    
    # STEP 4: Analyze
    info "Step 4/4: Analyzing results..."
    echo ""
    
    if echo "$sell_result" | grep -q '"status":"0x1"'; then
        # SUCCESS
        local final_wpls recovered loss loss_percent
        final_wpls=$(get_balance "$WPLS" "$USER")
        recovered=$((final_wpls - initial_wpls + TEST_AMOUNT))
        loss=$((TEST_AMOUNT - recovered))
        loss_percent=$(( loss * 100 / TEST_AMOUNT ))
        
        echo -e "${GREEN}======================================${NC}"
        echo -e "${GREEN}  ✓ NOT A HONEYPOT${NC}"
        echo -e "${GREEN}======================================${NC}"
        echo "Token can be bought and sold"
        echo "Loss from fees/slippage: ~${loss_percent}%"
        
        return 0
    else
        # FAILURE
        echo -e "${RED}======================================${NC}"
        echo -e "${RED}  ⚠ HONEYPOT DETECTED${NC}"
        echo -e "${RED}======================================${NC}"
        echo "Token was bought but CANNOT be sold"
        echo ""
        
        if echo "$sell_result" | grep -qi "STF"; then
            error "Type: Transfer block (SafeTransferFrom failed)"
        elif echo "$sell_result" | grep -qi "TRANSFER_FAILED"; then
            error "Type: Transfer function blocked"
        else
            error "Type: Unknown block mechanism"
            echo "Error details:"
            echo "$sell_result" | grep -o '"revertReason":"[^"]*"' || echo "No revert reason"
        fi
        
        return 1
    fi
}

main "$@"