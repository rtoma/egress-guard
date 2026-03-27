# Quick Start Guide

## Build

```bash
go build -o egress-proxy cmd/main.go
```

## Run Locally

```bash
# With example config
CONFIGMAP_PATH=./egress-policy.yaml LOG_LEVEL=INFO ./egress-proxy
```

## Test

```bash
# Run all tests
go test ./... -v

# Run tests with coverage
go test ./... -cover

# Run specific package tests
go test ./internal/config -v
```

## Docker Build

```bash
docker build -t k8s-egress-guard:latest .
```

## Configuration

Edit `egress-policy.yaml`:

```yaml
identities:
  "frontend-services":
    api_keys:
      - "frontend-pod-1"
      - "frontend-pod-2"
    allowed_destinations:
      - "api.example.com"       # Exact domain
      - "*.cdn.example.com"     # Wildcard suffix

  "backend-services":
    api_keys:
      - "backend-worker-1"
    allowed_destinations:
      - "*.googleapis.com"
      - "10.0.0.0/24"           # CIDR range
```

**Identity names** are arbitrary labels — they are not matched against pod names. Access is granted based on the `api_keys` list within each identity.

**API Keys**: must be unique across all identities. Exact match only — no wildcards.

**Destination Patterns**:
- Exact domain: `api.example.com`
- Wildcard suffix: `*.example.com` (matches `api.example.com`, `v1.api.example.com`)
- IP address: `192.168.1.1`
- CIDR range: `10.0.0.0/24`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `4750` | Proxy listener port |
| `METRICS_PORT` | `9090` | Health/metrics port |
| `CONFIGMAP_PATH` | `/etc/config/egress-policy.yaml` | Config file path |
| `WATCH_INTERVAL` | `5` | Config reload interval (seconds) |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARN, ERROR) |

## Proxy Usage

```bash
# Set identity as username in proxy auth
export PROXY_USER="pod-frontend"
export PROXY_PASS="any-password"

# Make request through proxy
curl -x http://localhost:4750 \
     -U "$PROXY_USER:$PROXY_PASS" \
     https://api.example.com
```

## Health Check

```bash
curl http://localhost:9090/health
# {"status":"healthy"}
```

## Metrics

```bash
curl http://localhost:9090/metrics | grep egress_proxy
```

Key metrics:
- `egress_proxy_requests_total{identity,destination,status}`
- `egress_proxy_config_reloads_total`
- `egress_proxy_config_load_errors_total`
- `egress_proxy_allowed_destinations{identity}`

## Troubleshooting

### Enable Debug Logging

```bash
LOG_LEVEL=DEBUG ./egress-proxy
```

### Check Config Syntax

```bash
cat egress-policy.yaml | yamllint -
```

### Verify Identity Matching

Check logs for identity matching:
```json
{"timestamp":"...","level":"INFO","message":"proxy request","identity":"pod-frontend","destination":"api.example.com","action":"allowed","status":"allowed"}
```

### Common Status Values

- `allowed` - Request permitted and tunneled
- `denied` - Destination not in allowed list
- `auth_required` - Missing Proxy-Authorization header
- `bad_request` - Malformed CONNECT request
- `connection_failed` - Unable to reach destination
- `sni_mismatch` - SNI hostname doesn't match allowed destination

## Project Structure

```
k8s-egress-guard/
├── cmd/
│   └── main.go                 # Application entry point
├── internal/
│   ├── config/                 # Configuration management
│   │   ├── config.go
│   │   └── config_test.go
│   ├── logging/                # Structured logging
│   │   └── logger.go
│   ├── metrics/                # Prometheus metrics
│   │   └── metrics.go
│   └── proxy/                  # HTTP CONNECT proxy
│       └── server.go
├── egress-policy.yaml          # Example configuration
├── Dockerfile                  # Container build
├── README.md                   # Full documentation
├── QUICKSTART.md               # This file
├── CONTRIBUTING.md             # Contribution guide
├── LICENSE                     # Apache 2.0
├── test.sh                     # Test runner script
└── go.mod                      # Go dependencies
```
