#!/bin/bash
while true; do
    clear
    echo "=== BATCH PROGRESS ==="
    echo "Last updated: $(date)"
    echo ""
    grep -E "Token [0-9]+/15" /home/egftdlnx/projects/honeypot-detector/logs/batch_results_FINAL.log 2>/dev/null | tail -1
    echo ""
    echo "=== RECENT RESULTS ==="
    grep -E "(✅ SAFE|🔴 HONEYPOT|Success Rate:|holders tested)" /home/egftdlnx/projects/honeypot-detector/logs/batch_results_FINAL.log 2>/dev/null | tail -10
    echo ""
    echo "Press Ctrl+C to stop monitoring"
    sleep 10
done
