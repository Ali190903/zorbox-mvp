#!/usr/bin/env bash
# ZORBOX Smoke Test - Linux/macOS
set -e

echo "=== ZORBOX Smoke Test ==="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

FAILED=0

# Test function
test_endpoint() {
    local name="$1"
    local url="$2"
    echo -n "Testing $name... "
    if curl -sf -m 5 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        FAILED=$((FAILED + 1))
    fi
}

# Health checks
echo "--- Health Checks ---"
test_endpoint "Orchestrator Health" "http://localhost:8080/healthz"
test_endpoint "Reporter Health" "http://localhost:8090/healthz"
test_endpoint "TI Enrichment Health" "http://localhost:8070/healthz"
test_endpoint "Static Analyzer Health" "http://localhost:8060/healthz"
test_endpoint "Sandbox Native Health" "http://localhost:8050/healthz"

echo ""
echo "--- Metrics Endpoints ---"
test_endpoint "Orchestrator Metrics" "http://localhost:8080/metrics"
test_endpoint "Reporter Metrics" "http://localhost:8090/metrics"
test_endpoint "TI Metrics" "http://localhost:8070/metrics"
test_endpoint "Static Analyzer Metrics" "http://localhost:8060/metrics"
test_endpoint "Sandbox Metrics" "http://localhost:8050/metrics"

echo ""
echo "--- Monitoring Stack ---"
test_endpoint "Prometheus" "http://localhost:9090/-/healthy"
test_endpoint "Grafana" "http://localhost:3000/api/health"

echo ""
echo "=== Results ==="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILED test(s) failed!${NC}"
    exit 1
fi
