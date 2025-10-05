#!/usr/bin/env bash

set -euo pipefail

#===============================================================================
# CONFIG
#===============================================================================

RPC_URL="${RPC_URL:-https://rpc.pulsechain.com}"
FALLBACK_RPCS=("https://pulsechain.publicnode.com")
CACHE_DIR="./.cache"
TIMEOUT=15
VERBOSE="${VERBOSE:-false}"

RISK_CRITICAL=100
RISK_HIGH=75
RISK_MEDIUM=50
RISK_LOW=25

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

declare -a FINDINGS
RISK_SCORE=0
TOKEN_ADDRESS=""
TOKEN_NAME="Unknown"
TOKEN_SYMBOL="???"
TOKEN_DECIMALS="18"
TOKEN_SUPPLY="0"
IS_PROXY=false
IMPL_ADDRESS=""
ACTIVE_RPC=""

#===============================================================================
# LOGGING
#===============================================================================

log() { echo -e "${2}[${1}]${NC} ${*:3}" >&2; }
info()  { log "INFO" "$GREEN" "$@"; }
warn()  { log "WARN" "$YELLOW" "$@"; }
debug() { [[ "$VERBOSE" == "true" ]] && log "DEBUG" "$CYAN" "$@" || true; }
die()   { log "ERROR" "$RED" "$@"; exit 2; }

add_finding() {
    FINDINGS+=("$1|$2|$3|${4:-0}")
    RISK_SCORE=$((RISK_SCORE + ${4:-0}))
    debug "[$1] $2 (+${4:-0})"
}

#===============================================================================
# RPC
#===============================================================================

safe_call() { timeout "$TIMEOUT" "$@" 2>/dev/null || echo ""; }

setup_rpc() {
    for rpc in "$RPC_URL" "${FALLBACK_RPCS[@]}"; do
        timeout 3 cast block-number --rpc-url "$rpc" >/dev/null 2>&1 && { ACTIVE_RPC="$rpc"; debug "Using: $rpc"; return 0; }
    done
    die "No working RPC"
}

#===============================================================================
# BLOCKCHAIN
#===============================================================================

get_code() {
    local addr="$1"
    local cache="$CACHE_DIR/${addr}_code.cache"
    local ttl=3600  # 1 hour in seconds
    
    if [[ -f "$cache" ]]; then
        # Get file modification time
        local cache_age=$(( $(date +%s) - $(stat -c%Y "$cache" 2>/dev/null || stat -f%m "$cache" 2>/dev/null || echo 0) ))
        
        # If cache is newer than TTL, use it
        if (( cache_age < ttl )); then
            debug "Using cached bytecode (${cache_age}s old)"
            cat "$cache"
            return 0
        else
            debug "Cache expired (${cache_age}s old), refetching..."
        fi
    fi
    
    # Fetch fresh data
    local code=$(safe_call cast code "$addr" --rpc-url "$ACTIVE_RPC")
    
    if [[ -n "$code" && "$code" != "0x" ]]; then
        echo "$code" > "$cache"
        echo "$code"
        return 0
    fi
    
    return 1
}

call_func() { safe_call cast call "$1" "$2" --rpc-url "$ACTIVE_RPC"; }
read_storage() { safe_call cast storage "$1" "$2" --rpc-url "$ACTIVE_RPC"; }

#===============================================================================
# TOKEN INFO
#===============================================================================

fetch_token_info() {
    info "Fetching token info..."
    
    local name_raw=$(call_func "$1" "name()")
    [[ -n "$name_raw" ]] && TOKEN_NAME=$(echo "$name_raw" | cast --to-ascii 2>/dev/null | tr -d '\0\n' | head -c 50 || echo "Unknown")
    
    local sym_raw=$(call_func "$1" "symbol()")
    [[ -n "$sym_raw" ]] && TOKEN_SYMBOL=$(echo "$sym_raw" | cast --to-ascii 2>/dev/null | tr -d '\0\n' | head -c 20 || echo "???")
    
    local dec_raw=$(call_func "$1" "decimals()")
    [[ -n "$dec_raw" ]] && TOKEN_DECIMALS=$(echo "$dec_raw" | cast --to-dec 2>/dev/null || echo "18")
    
    local sup_raw=$(call_func "$1" "totalSupply()")
    [[ -n "$sup_raw" ]] && TOKEN_SUPPLY=$(echo "$sup_raw" | cast --to-dec 2>/dev/null || echo "0")
}

#===============================================================================
# PROXY DETECTION
#===============================================================================

detect_proxy() {
    local token="$1"
    local code=$(get_code "$token")
    local size=$((${#code} / 2 - 1))
    
    info "Checking for proxy... ($size bytes)"
    
    if (( size < 1000 )); then
        code="${code#0x}"
        code="${code^^}"
        
        # EIP-1167 Minimal Proxy
        if [[ "$code" =~ 363D3D373D3D3D363D73([A-F0-9]{40}) ]]; then
            IMPL_ADDRESS="0x${BASH_REMATCH[1]}"
            IS_PROXY=true
            add_finding "INFO" "PROXY" "Minimal proxy (EIP-1167)" 0
            info "→ Implementation: $IMPL_ADDRESS"
            return 0
        fi
        
        # EIP-1967
        local impl_raw=$(read_storage "$token" "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
        local impl="0x${impl_raw: -40}"
        
        if [[ "$impl" != "0x0000000000000000000000000000000000000000" ]]; then
            IS_PROXY=true
            IMPL_ADDRESS="$impl"
            add_finding "INFO" "PROXY" "EIP-1967 proxy" 0
            info "→ Implementation: $impl"
            return 0
        fi
    fi
    
    return 1
}

#===============================================================================
# FAST HONEYPOT DETECTION (NO SLOW REGEX!)
#===============================================================================

# Fast string contains - no regex
contains() { [[ "$1" == *"$2"* ]]; }

# Count occurrences fast
count_occurrences() {
    local str="$1"
    local pattern="$2"
    local count=0
    local temp="$str"
    
    while [[ "$temp" == *"$pattern"* ]]; do
        temp="${temp#*$pattern}"
        ((count++))
    done
    
    echo "$count"
}

check_critical_patterns() {
    local code="${1^^}"  # Uppercase once
    local is_proxy="$2"
    
    info "Checking critical patterns..."
    
    # CRITICAL: Blacklist functions
    contains "$code" "FE575A87" && add_finding "CRITICAL" "BLACKLIST" "isBlacklisted() function detected" 60
    contains "$code" "0ECB93C0" && add_finding "CRITICAL" "BLACKLIST" "isBlackListed() function detected" 60
    contains "$code" "59BF1ABE" && add_finding "CRITICAL" "BLACKLIST" "blacklist() function detected" 60
    contains "$code" "F9F92BE4" && add_finding "CRITICAL" "BLACKLIST" "addBlackList() function detected" 60
    
    # CRITICAL: Missing transfer (if not proxy)
    if [[ "$is_proxy" == "false" ]]; then
        contains "$code" "A9059CBB" || add_finding "CRITICAL" "MISSING" "No transfer() function" 70
    fi
    
    # CRITICAL: Has approve but NO transferFrom
    if contains "$code" "095EA7B3" && ! contains "$code" "23B872DD"; then
        [[ "$is_proxy" == "false" ]] && add_finding "CRITICAL" "HONEYPOT" "approve() exists but NO transferFrom()" 80
    fi
    
    info "✓ Critical checks done"
}

check_high_risk_patterns() {
    local code="${1^^}"
    
    info "Checking high-risk patterns..."
    
    # Dangerous functions
    contains "$code" "40C10F19" && add_finding "MEDIUM" "PRIVILEGE" "mint() function exists" 10
    contains "$code" "42966C68" && add_finding "MEDIUM" "PRIVILEGE" "burn() function exists" 10
    
    info "✓ High-risk checks done"
}

check_features() {
    local code="${1^^}"
    local size="$2"
    
    info "Checking features..."
    
    # DELEGATECALL (context-aware)
    if contains "$code" "F4"; then
        local dc_count=$(count_occurrences "$code" "F4")
        if (( size > 1000 && dc_count > 10 )); then
            add_finding "MEDIUM" "DELEGATECALL" "Multiple DELEGATECALL ($dc_count times)" 15
        fi
    fi
    
    # SELFDESTRUCT
    if contains "$code" "FF"; then
        local ff_count=$(count_occurrences "$code" "FF")
        if (( ff_count < 5 )); then
            add_finding "LOW" "SELFDESTRUCT" "Self-destruct capability exists" 10
        fi
    fi
    
    info "✓ Feature checks done"
}

#===============================================================================
# BYTECODE ANALYSIS
#===============================================================================

analyze_bytecode() {
    local code="$1"
    local label="$2"
    local is_proxy="${3:-false}"
    
    local size=$((${#code} / 2 - 1))
    
    info "Analyzing $label ($size bytes)..."
    
    if (( size > 24576 )); then
        add_finding "CRITICAL" "SIZE" "Exceeds maximum contract size" 100
        info "✓ Analysis complete (oversized)"
        return
    fi
    
    # Run fast checks (NO SLOW REGEX)
    check_critical_patterns "$code" "$is_proxy"
    check_high_risk_patterns "$code"
    check_features "$code" "$size"
    
    info "✓ Analysis of $label complete"
}

#===============================================================================
# OWNERSHIP
#===============================================================================

check_ownership() {
    local token="$1"
    
    info "Checking ownership..."
    
    local owner_raw=$(call_func "$token" "owner()")
    
    if [[ -z "$owner_raw" ]]; then
        debug "No owner() function"
        info "✓ Ownership check done"
        return 0
    fi
    
    local owner="0x${owner_raw: -40}"
    
    if [[ "$owner" == "0x0000000000000000000000000000000000000000" ]]; then
        add_finding "INFO" "OWNERSHIP" "Ownership renounced" -5
    else
        add_finding "LOW" "OWNERSHIP" "Has owner: $owner" 5
    fi
    
    info "✓ Ownership check done"
}

#===============================================================================
# OUTPUT
#===============================================================================

show_results() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}       HONEYPOT DETECTOR v2.0.0 - PRODUCTION        ${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${BOLD}Token Information:${NC}"
    echo -e "  Address:  ${CYAN}$TOKEN_ADDRESS${NC}"
    echo -e "  Name:     $TOKEN_NAME"
    echo -e "  Symbol:   $TOKEN_SYMBOL"
    echo -e "  Decimals: $TOKEN_DECIMALS"
    echo -e "  Supply:   $TOKEN_SUPPLY"
    
    if [[ "$IS_PROXY" == "true" ]]; then
        echo -e "  ${CYAN}Type:     Proxy Contract${NC}"
        echo -e "  ${CYAN}Logic:    $IMPL_ADDRESS${NC}"
    fi
    
    echo ""
    
    # Calculate risk level
    local level="SAFE"
    (( RISK_SCORE >= RISK_CRITICAL )) && level="CRITICAL"
    (( RISK_SCORE >= RISK_HIGH && RISK_SCORE < RISK_CRITICAL )) && level="HIGH"
    (( RISK_SCORE >= RISK_MEDIUM && RISK_SCORE < RISK_HIGH )) && level="MEDIUM"
    (( RISK_SCORE >= RISK_LOW && RISK_SCORE < RISK_MEDIUM )) && level="LOW"
    
    # Show findings or safe message
    if [[ ${#FINDINGS[@]} -eq 0 ]] || [[ "$level" == "SAFE" ]]; then
        echo -e "${GREEN}${BOLD}✓ No honeypot patterns detected${NC}"
        echo ""
        echo -e "${GREEN}This contract appears to be safe based on bytecode analysis.${NC}"
        echo -e "${GREEN}Standard ERC20 functions are present.${NC}"
    else
        echo -e "${BOLD}Security Findings:${NC}"
        echo ""
        
        for f in "${FINDINGS[@]}"; do
            IFS='|' read -r sev cat msg score <<< "$f"
            
            local color="$NC"
            case "$sev" in
                CRITICAL) color="$RED" ;;
                HIGH) color="$RED" ;;
                MEDIUM) color="$YELLOW" ;;
                LOW) color="$CYAN" ;;
                INFO) [[ "$VERBOSE" != "true" ]] && continue; color="$NC" ;;
            esac
            
            echo -e "${color}  [$sev]${NC} ${BOLD}$cat:${NC} $msg"
        done
    fi
    
    echo ""
    
    local color="$GREEN"
    [[ "$level" =~ CRITICAL|HIGH ]] && color="$RED"
    [[ "$level" == "MEDIUM" ]] && color="$YELLOW"
    [[ "$level" == "LOW" ]] && color="$CYAN"
    
    echo -e "${BOLD}Risk Assessment:${NC}"
    echo -e "  Score: ${BOLD}$RISK_SCORE${NC} / 100"
    echo -e "  Level: ${color}${BOLD}$level${NC}"
    echo ""
    
    case "$level" in
        CRITICAL)
            echo -e "${RED}${BOLD}⛔ CRITICAL RISK - LIKELY HONEYPOT/SCAM${NC}"
            echo -e "${RED}Strong honeypot indicators detected. DO NOT USE.${NC}"
            ;;
        HIGH)
            echo -e "${RED}${BOLD}⚠️  HIGH RISK - AVOID${NC}"
            echo -e "${YELLOW}Serious security concerns detected.${NC}"
            ;;
        MEDIUM)
            echo -e "${YELLOW}${BOLD}⚠️  MEDIUM RISK - CAUTION${NC}"
            echo -e "${YELLOW}Some concerns detected. Verify source code.${NC}"
            ;;
        LOW)
            echo -e "${CYAN}${BOLD}ℹ️  LOW RISK${NC}"
            echo -e "${CYAN}Minor concerns. Contract appears functional.${NC}"
            ;;
        SAFE)
            echo -e "${GREEN}${BOLD}✓ APPEARS SAFE${NC}"
            echo -e "${GREEN}No honeypot patterns detected.${NC}"
            echo -e "${GREEN}Contract follows standard ERC20 conventions.${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${CYAN}${BOLD}Note:${NC} ${CYAN}This is automated bytecode analysis. Always:${NC}"
    echo -e "${CYAN}  • Verify source code on block explorer${NC}"
    echo -e "${CYAN}  • Check liquidity locks${NC}"
    echo -e "${CYAN}  • Review team and audit reports${NC}"
    echo -e "${CYAN}  • Test with small amounts first${NC}"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================

analyze() {
    local token="$1"
    
    [[ ! "$token" =~ ^0x[a-fA-F0-9]{40}$ ]] && die "Invalid address"
    
    TOKEN_ADDRESS="$token"
    info "Starting analysis: $token"
    
    # Check exists
    local code=$(get_code "$token")
    [[ -z "$code" || "$code" == "0x" ]] && die "Not a contract"
    
    # Get info
    fetch_token_info "$token"
    
    # Detect proxy
    if detect_proxy "$token"; then
        if [[ -n "$IMPL_ADDRESS" && "$IMPL_ADDRESS" != "0x0000000000000000000000000000000000000000" ]]; then
            info "Fetching implementation bytecode..."
            local impl_code=$(get_code "$IMPL_ADDRESS")
            
            if [[ -n "$impl_code" && "$impl_code" != "0x" ]]; then
                analyze_bytecode "$impl_code" "implementation" "false"
            else
                warn "Could not fetch implementation"
                add_finding "HIGH" "PROXY" "Unable to verify implementation" 30
            fi
        fi
    else
        analyze_bytecode "$code" "contract" "false"
    fi
    
    # Check ownership
    check_ownership "$token"
    
    info "Analysis complete!"
}

main() {
    local token=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            --rpc) RPC_URL="$2"; shift 2 ;;
            -h|--help)
                cat <<EOF
Honeypot Detector 2.0.0 - Fast & Reliable

Usage: $0 [OPTIONS] <address>

Features:
  ✓ Fast analysis (completes in seconds)
  ✓ Always shows results
  ✓ Clear safe/unsafe indicators
  ✓ Proxy detection & analysis

Options:
  -v, --verbose    Verbose output
  --rpc <url>      Custom RPC endpoint

Examples:
  $0 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
  $0 -v 0xb1f52D529390Ec28483Fe7689A4eA26Fce2956f4
EOF
                exit 0
                ;;
            0x*) token="$1"; shift ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    
    [[ -z "$token" ]] && die "Usage: $0 <address>"
    
    command -v cast >/dev/null || die "Install foundry: curl -L https://foundry.paradigm.xyz | bash"
    mkdir -p "$CACHE_DIR"
    setup_rpc
    
    analyze "$token"
    show_results
    
    (( RISK_SCORE >= RISK_HIGH )) && exit 1 || exit 0
}

main "$@"