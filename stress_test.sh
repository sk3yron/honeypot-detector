#!/bin/bash
# Honeypot Detector Stress Test Suite
# Tests system performance, reliability, and error handling under load

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
DETECTOR="./target/release/honeypot-detector"
LOG_FILE="stress_test_results.log"
START_TIME=$(date +%s)

# Test tokens (mix of safe, risky, and edge cases)
declare -a TEST_TOKENS=(
    "0xA1077a294dDE1B09bB078844df40758a5D0f9a27"  # WPLS - Known safe
    "0x95B303987A60C71504D99Aa1b13B4DA07b0790ab"  # PLSX - Known safe
    "0xaAE18Cd46C45d343BbA1eab46716B4D69d799734"  # BAR - Previously tested safe
    "0x921Bc9A18EaF7299Ae42c1cc416ef070b04EF81E"  # Previously tested safe
    "0x2fa878Ab3F87CC1C9737Fc071108F904c0B0C95d"  # DAI - Known safe
    "0x0Cb6F5a34ad42ec934882A05265A7d5F59b51A2f"  # INC - Test token
)

# Invalid addresses for error testing
declare -a INVALID_ADDRESSES=(
    "0x0000000000000000000000000000000000000000"  # Zero address
    "0xInvalidAddress"                              # Invalid format
    "not_an_address"                                # Completely invalid
)

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TOTAL_TIME=0

echo "=================================================================="
echo "🔬 HONEYPOT DETECTOR STRESS TEST SUITE"
echo "=================================================================="
echo ""
echo "Start Time: $(date)"
echo "Log File: $LOG_FILE"
echo ""

# Clean previous log
> "$LOG_FILE"

# Ensure binary is built
echo -e "${BLUE}📦 Building release binary...${NC}"
cargo build --release 2>&1 | grep -E "Compiling|Finished" || true
echo ""

# Function to run a single test
run_test() {
    local token=$1
    local test_name=$2
    local test_num=$3
    local flags=$4
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${YELLOW}Test $test_num: $test_name${NC}"
    echo "  Address: $token"
    echo "  Flags: $flags"
    
    local start=$(date +%s.%N)
    
    if $DETECTOR "$token" $flags >> "$LOG_FILE" 2>&1; then
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc)
        TOTAL_TIME=$(echo "$TOTAL_TIME + $duration" | bc)
        
        echo -e "  ${GREEN}✅ PASSED${NC} (${duration}s)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo "PASS: $test_name (${duration}s)" >> "$LOG_FILE"
    else
        local end=$(date +%s.%N)
        local duration=$(echo "$end - $start" | bc)
        
        echo -e "  ${RED}❌ FAILED${NC} (${duration}s)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "FAIL: $test_name (${duration}s)" >> "$LOG_FILE"
    fi
    echo ""
}

# Function to run concurrent tests
run_concurrent_test() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}🔀 CONCURRENT EXECUTION TEST${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local start=$(date +%s.%N)
    
    # Launch multiple analyses in background
    local pids=()
    for i in {0..2}; do
        token=${TEST_TOKENS[$i]}
        echo "Launching concurrent analysis $((i+1)): $token"
        $DETECTOR "$token" --no-claude > "/tmp/stress_test_$i.log" 2>&1 &
        pids+=($!)
    done
    
    # Wait for all to complete
    echo ""
    echo "Waiting for all concurrent tests to complete..."
    for pid in "${pids[@]}"; do
        wait $pid && echo "  Process $pid completed successfully" || echo "  Process $pid failed"
    done
    
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    
    echo ""
    echo -e "${GREEN}✅ Concurrent test completed in ${duration}s${NC}"
    echo ""
}

# Function to test memory usage
check_memory() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}💾 MEMORY USAGE TEST${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Get memory before
    local mem_before=$(free -m | awk 'NR==2{print $3}')
    
    # Run 5 analyses
    for i in {0..4}; do
        token=${TEST_TOKENS[$i]}
        echo "Running analysis $((i+1))/5: $token"
        $DETECTOR "$token" --no-claude > /dev/null 2>&1 || true
    done
    
    # Get memory after
    local mem_after=$(free -m | awk 'NR==2{print $3}')
    local mem_used=$((mem_after - mem_before))
    
    echo ""
    echo "Memory Before: ${mem_before}MB"
    echo "Memory After:  ${mem_after}MB"
    echo "Memory Used:   ${mem_used}MB"
    echo ""
}

# ============================================================
# TEST SUITE 1: Sequential Analysis (No Claude)
# ============================================================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📊 TEST SUITE 1: Sequential Analysis (No Claude)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

test_num=1
for token in "${TEST_TOKENS[@]}"; do
    run_test "$token" "Sequential analysis #$test_num" "$test_num" "--no-claude"
    test_num=$((test_num + 1))
done

# ============================================================
# TEST SUITE 2: Rapid Succession (Same Token)
# ============================================================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}⚡ TEST SUITE 2: Rapid Succession (Cache Test)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

token="${TEST_TOKENS[0]}"
for i in {1..3}; do
    run_test "$token" "Rapid succession #$i (WPLS)" "$((test_num))" "--no-claude"
    test_num=$((test_num + 1))
done

# ============================================================
# TEST SUITE 3: Error Handling
# ============================================================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}⚠️  TEST SUITE 3: Error Handling${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

for addr in "${INVALID_ADDRESSES[@]}"; do
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}Test $test_num: Invalid address handling${NC}"
    echo "  Address: $addr"
    
    # For invalid addresses, we expect failure
    if ! $DETECTOR "$addr" --no-claude >> "$LOG_FILE" 2>&1; then
        echo -e "  ${GREEN}✅ PASSED${NC} (Error handled correctly)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}❌ FAILED${NC} (Should have rejected invalid address)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
    test_num=$((test_num + 1))
done

# ============================================================
# TEST SUITE 4: Concurrent Execution
# ============================================================
run_concurrent_test

# ============================================================
# TEST SUITE 5: Memory Usage
# ============================================================
check_memory

# ============================================================
# FINAL REPORT
# ============================================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "=================================================================="
echo "📊 STRESS TEST RESULTS"
echo "=================================================================="
echo ""
echo "Total Tests:     $TOTAL_TESTS"
echo "Passed:          $PASSED_TESTS ($(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc)%)"
echo "Failed:          $FAILED_TESTS ($(echo "scale=1; $FAILED_TESTS * 100 / $TOTAL_TESTS" | bc)%)"
echo ""
echo "Total Runtime:   ${ELAPSED}s"
echo "Average Time:    $(echo "scale=2; $TOTAL_TIME / $TOTAL_TESTS" | bc)s per test"
echo ""
echo "Log File:        $LOG_FILE"
echo "End Time:        $(date)"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo ""
    echo "Check $LOG_FILE for details"
    exit 1
fi
