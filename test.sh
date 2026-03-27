#!/bin/bash

# Test script for k8s-egress-guard
# This script demonstrates basic functionality without actually running the proxy

set -e

echo "=== k8s-egress-guard Test Script ==="
echo

# Check if binary exists
if [ ! -f "./egress-proxy" ]; then
    echo "❌ Binary not found. Run: go build -o egress-proxy cmd/main.go"
    exit 1
fi

echo "✓ Binary found: egress-proxy"

# Check if config exists
if [ ! -f "./egress-policy.yaml" ]; then
    echo "❌ Config file not found: egress-policy.yaml"
    exit 1
fi

echo "✓ Config file found: egress-policy.yaml"

# Run tests
echo
echo "Running tests..."
go test ./... -cover

echo
echo "✓ All tests passed!"

echo
echo "=== Build Information ==="
ls -lh egress-proxy

echo
echo "=== To run the proxy locally ==="
echo "  CONFIGMAP_PATH=./egress-policy.yaml LOG_LEVEL=DEBUG ./egress-proxy"
echo
echo "=== To test with curl ==="
echo "  curl -x http://localhost:4750 -U 'pod-frontend:password' https://api.example.com"
echo
echo "=== Health & Metrics ==="
echo "  curl http://localhost:9090/health"
echo "  curl http://localhost:9090/metrics"
