# egress-guard

[![CI](https://github.com/rtoma/egress-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rtoma/egress-guard/actions/workflows/ci.yml)
[![Docker](https://github.com/rtoma/egress-guard/actions/workflows/docker.yml/badge.svg)](https://github.com/rtoma/egress-guard/actions/workflows/docker.yml)

A Kubernetes egress proxy that controls outbound traffic from pods to approved destinations based on pod identity.

## Overview

egress-guard is an HTTP CONNECT proxy written in Go that enforces egress policies for Kubernetes workloads. It authenticates pods via `Proxy-Authorization` headers and validates both the requested destination and SNI hostname during TLS handshakes to prevent DNS rebinding attacks.

## Features

- **API Key-based Access Control**: Authenticate via Proxy-Authorization header using exact API key matching
- **Flexible Destination Matching**: Support for exact domains, wildcard suffixes, IP addresses, and CIDR ranges
- **SNI Validation**: Extracts and validates SNI hostname from TLS ClientHello to prevent DNS rebinding
- **Hot Configuration Reload**: Automatically reloads policy changes without restart
- **Prometheus Metrics**: Comprehensive metrics for monitoring and alerting
- **Structured JSON Logging**: Audit trail of all connection attempts
- **Graceful Shutdown**: Handles SIGINT/SIGTERM with connection draining

## Architecture

```
┌─────────────┐                 ┌──────────────────┐                 ┌─────────────┐
│             │  CONNECT req    │                  │  TCP tunnel     │             │
│  Pod/Client ├────────────────►│  Egress Proxy    ├────────────────►│ Destination │
│             │  + Proxy-Auth   │  (Port 4750)     │                 │             │
└─────────────┘                 └──────────────────┘                 └─────────────┘
                                         │
                                         │ Metrics/Health
                                         ▼
                                ┌──────────────────┐
                                │  Metrics Server  │
                                │  (Port 9090)     │
                                │  /health         │
                                │  /metrics        │
                                └──────────────────┘
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `4750` | Proxy listener port |
| `METRICS_PORT` | `9090` | Metrics/health endpoint port |
| `CONFIGMAP_PATH` | `/etc/config/egress-policy.yaml` | Path to policy configuration |
| `WATCH_INTERVAL` | `5` | Config file watch interval (seconds) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARN, ERROR) |

### Policy Configuration

The policy is defined in a YAML file (typically mounted from a ConfigMap):

```yaml
identities:
  # Frontend services
  "frontend-services":
    api_keys:
      - "frontend-pod-1"
      - "frontend-pod-2"
    allowed_destinations:
      - "api.example.com"           # Exact domain
      - "*.cdn.example.com"         # Wildcard suffix

  # Backend services
  "backend-services":
    api_keys:
      - "backend-worker-1"
      - "backend-worker-2"
    allowed_destinations:
      - "*.googleapis.com"          # Multiple services
      - "db.internal.svc.cluster.local"
      - "10.0.0.0/24"              # CIDR range

  # Monitoring services
  "monitoring-services":
    api_keys:
      - "prometheus"
      - "alertmanager"
    allowed_destinations:
      - "prometheus.internal"
      - "192.168.1.100"            # Specific IP
```

**API Key Matching**:
- Exact match required (no wildcards)
- API keys must be unique across all identities

**Destination Matching** (priority order):
1. Exact domain (case-insensitive)
2. Wildcard suffix (`*.example.com` matches `api.example.com`)
3. CIDR range (`10.0.0.0/24`)
4. Exact IP address

## Usage

### Building

```bash
go build -o egress-proxy cmd/main.go
```

### Running Locally

```bash
# With default config path
./egress-proxy

# With custom config
CONFIGMAP_PATH=./egress-policy.yaml LOG_LEVEL=DEBUG ./egress-proxy
```

### Testing with curl

```bash
# Set up proxy authentication (username = API key)
export PROXY_USER="frontend-pod-1"
export PROXY_PASS="any-password"

# Make request through proxy
curl -x http://localhost:4750 \
     -U "$PROXY_USER:$PROXY_PASS" \
     https://api.example.com

# Check health
curl http://localhost:9090/health

# View metrics
curl http://localhost:9090/metrics
```

### Kubernetes Deployment

Example deployment (simplified):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: egress-policy
data:
  egress-policy.yaml: |
    identities:
      "frontend-services":
        api_keys: ["frontend-pod-1"]
        allowed_destinations: ["api.example.com"]
      "backend-services":
        api_keys: ["backend-worker-1"]
        allowed_destinations: ["*.googleapis.com"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: egress-proxy
spec:
  selector:
    matchLabels:
      app: egress-proxy
  template:
    metadata:
      labels:
        app: egress-proxy
    spec:
      containers:
      - name: egress-proxy
        image: your-registry/egress-proxy:latest
        ports:
        - containerPort: 4750
          name: proxy
        - containerPort: 9090
          name: metrics
        env:
        - name: LOG_LEVEL
          value: "INFO"
        volumeMounts:
        - name: config
          mountPath: /etc/config
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: egress-policy
```

## Metrics

Prometheus metrics exposed on `/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `egress_proxy_requests_total` | Counter | identity, destination, status | Total proxy requests |
| `egress_proxy_config_reloads_total` | Counter | - | Successful config reloads |
| `egress_proxy_config_load_errors_total` | Counter | - | Config load errors |
| `egress_proxy_allowed_destinations` | Gauge | identity | Allowed destinations per identity |

**Status Values**: `allowed`, `denied`, `auth_required`, `bad_request`, `connection_failed`, `sni_mismatch`

## Security Features

### SNI Validation

The proxy extracts the Server Name Indication (SNI) hostname from the TLS ClientHello and validates it against the allowed destinations. This prevents DNS rebinding attacks where an attacker:
1. Requests connection to an allowed domain
2. DNS resolves to a malicious IP
3. TLS handshake uses a different (non-allowed) hostname

If SNI validation fails, the connection is rejected with `403 Forbidden`.

### Authentication

Pods authenticate using the `Proxy-Authorization: Basic <base64>` header, where the username represents the pod identity. The password is ignored (can be any value).

### Logging

All connection attempts are logged in structured JSON format with:
- Timestamp
- Identity
- Destination
- Action (allowed/denied)
- Error details (if applicable)

**Never logged**: Proxy credentials, TLS keys, or sensitive headers

## Testing

Run the test suite:

```bash
# All tests
go test ./...

# Specific package
go test ./internal/config

# With coverage
go test -cover ./...

# Verbose output
go test -v ./...
```

## Project Structure

```
egress-guard/
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
│       ├── server.go
│       ├── request_handler.go
│       ├── tls_handler.go
│       └── bytes_counting_writer.go
├── e2e/                        # End-to-end tests
│   └── server_e2e_test.go
├── egress-policy.yaml          # Example configuration
├── CONTRIBUTING.md
├── LICENSE
├── go.mod
└── README.md
```

## Development

### Prerequisites

- Go 1.21+
- Access to a Kubernetes cluster (for deployment)

### Adding a New Feature

1. Update the appropriate package in `internal/`
2. Add tests in `*_test.go` files
3. Update metrics if needed
4. Update this README
5. Test locally before deploying

### Debugging

Enable debug logging:

```bash
LOG_LEVEL=DEBUG ./egress-proxy
```

This will log:
- Detailed request processing
- Config reload events
- SNI validation steps
- Connection lifecycle

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
