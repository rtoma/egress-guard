# Product requirements document

"Egress Guard" is a lightweight egress proxy for Kubernetes that enforces zero-trust networking by restricting outbound pod traffic to verified destinations.

## Project Overview

- **Purpose**: HTTP CONNECT proxy that enforces egress policies based on pod identity
- **Language**: Go
- **Config**: Kubernetes ConfigMap with hot reloading
- **Proxy Port**: 4750 (configurable)
- **Metrics Port**: 9090 (configurable)

## Core Requirements

### Configuration
- Load config from ConfigMap mounted at `/etc/config/egress-policy.yaml`
- Structure: Map of identity names → struct with api_keys list and allowed_destinations list
- Identity keys: logical name for the identity group
- API keys: exact string match required (no wildcards) - must be unique across all identities
- Allowed destinations: exact domain or prefix wildcard (starting with `*`), CIDR ranges, or IP addresses
- Hot reload: Watch file and reload on changes without restart
- Graceful error handling: Continue with last known good config on errors
- Duplicate detection: Reject config if any api_key appears in multiple identities

**Example Configuration**:
```yaml
identities:
  frontend-services:
    api_keys:
      - "frontend-pod-1"
      - "frontend-pod-2"
    allowed_destinations:
      - "api.example.com"
      - "*.cdn.example.com"

  backend-services:
    api_keys:
      - "backend-worker-1"
      - "backend-worker-2"
    allowed_destinations:
      - "*.googleapis.com"
      - "*.amazonaws.com"
      - "db.internal.svc.cluster.local"
      - "10.0.0.0/24"

  monitoring-services:
    api_keys:
      - "prometheus"
      - "alertmanager"
    allowed_destinations:
      - "prometheus.internal"
      - "*.datadog.com"
```

### Proxy Listener (Port 4750)

**Request Processing Flow**:
1. Parse HTTP CONNECT request (extract host and port)
2. Check for `Proxy-Authorization: Basic <base64>` header → extract username as API key
3. Look up API key in config (exact match only) → find which identity owns this key
4. Verify destination hostname is in allowed destinations list for that identity
5. Send `200 Connection Established`
6. Wait for TLS ClientHello (timeout: 5 seconds)
7. Validate traffic is TLS (first byte must be 0x16)
8. Extract SNI hostname from ClientHello
9. Validate SNI hostname against CONNECT destination and allowed list
10. If all validations pass, establish bidirectional TCP tunnel

**HTTP Response Codes**:
- `200 Connection Established` - Initial validation passed, awaiting TLS handshake
- `400 Bad Request` - Malformed CONNECT request, invalid host/port, or non-TLS traffic
- `403 Forbidden` - Missing SNI, SNI mismatch, or destination not in allowed list
- `407 Proxy Authentication Required` - Missing or invalid `Proxy-Authorization` header
- `408 Request Timeout` - TLS ClientHello not received within timeout
- `502 Bad Gateway` - Failed to connect to destination server

**SNI Validation (TLS-Only Proxy)**:
- **TLS Requirement**: This proxy ONLY supports HTTPS/TLS traffic
- All connections must present valid TLS ClientHello with SNI extension
- Non-TLS traffic is rejected with 400 Bad Request

**Validation Flow**:
1. After sending `200 Connection Established`, wait for TLS ClientHello (timeout: 5 seconds)
2. Verify first byte is `0x16` (TLS handshake record)
   - If not → Return 400 "Only HTTPS connections allowed"
3. Extract SNI hostname from ClientHello
   - If no SNI extension found → Return 403 "SNI extension required"
4. Validate SNI hostname (TWO requirements, both must pass):
   - SNI must match CONNECT destination hostname (case-insensitive)
     - Prevents DNS rebinding attacks
     - Example: CONNECT to 127.0.0.1 with SNI evil.com → BLOCKED
   - SNI must be in identity's allowed destinations list
     - Example: CONNECT to allowed.com with SNI notallowed.com → BLOCKED
5. If validation passes → establish tunnel
6. If validation fails → Return 403 Forbidden

**Error Handling**:
- ClientHello timeout (>5s) → 408 "Request timeout"
- Non-TLS traffic (first byte != 0x16) → 400 "Only HTTPS connections allowed"
- Missing SNI extension → 403 "SNI extension required"
- SNI hostname mismatch → 403 "SNI validation failed"
- SNI not in allowed list → 403 "Destination not allowed"
- Log all SNI validation failures at WARNING level
- Never bypass validation - all traffic must have valid SNI

**Implementation Details**:

1. **Hijack Connection Carefully**:
   - After `Hijack()`, the `readWriter.Reader` internal buffer panics if used directly
   - MUST read buffered data into byte slice with `io.ReadFull(readWriter.Reader, buf)`
   - Never pass `readWriter.Reader` to other goroutines or use it after extracting buffered data

2. **Efficient TLS Record Reading**:
   - Read TLS record header (5 bytes) first to determine record length
   - TLS record structure: [type(1), version(2), length(2), payload...]
   - Extract length from bytes 3-4 (big-endian): `len = data[3]<<8 | data[4]`
   - Peek/read exactly `5 + recordLen` bytes (typically 200-400 bytes for ClientHello)
   - **Never** use fixed-size peeks (e.g., Peek(1024)) - causes blocking/timeouts when actual data is smaller

3. **Synchronous Validation**:
   - Validate SNI **before** starting tunnel (not in parallel goroutine)
   - Prevents race conditions (goroutine closing connection during tunnel)
   - Validation sequence:
     a. Send `200 Connection Established`
     b. Wait for and read TLS ClientHello
     c. Extract and validate SNI
     d. If validation fails → send error response, return
     e. If validation passes → start tunnel with validated TLS data

4. **Tunnel Cleanup**:
   - Use buffered channel: `done := make(chan struct{}, 2)`
   - Wait for **both** directions: `<-done; <-done`
   - Prevents premature connection closure while one side still copying data

### Health & Metrics (Port 9090)
- `/health` endpoint: Return `{"status": "healthy"}` with 200 OK
- `/metrics` endpoint: Prometheus format metrics
  - `egress_proxy_requests_total{identity, destination, status}` counter
  - `egress_proxy_request_duration_seconds{identity, destination}` histogram
  - `egress_proxy_config_reloads_total` counter
  - `egress_proxy_config_load_errors_total` counter
  - `egress_proxy_allowed_destinations{identity}` gauge

Use `promauto` for metric registration.

### Logging & Observability
**Structured Logging** (JSON format):
- Standard fields: `timestamp`, `level`, `message`, `identity`, `destination`, `action`, `error`
- Log all CONNECT requests: identity, destination, allowed/denied decision
- Log config reload events: success, failure, number of identities loaded
- Log errors with full context (error type, stack trace)
- Log all SNI validation decisions at WARNING level:
  - Include: identity, CONNECT destination, SNI hostname, action (denied)
  - Log message examples: "SNI hostname mismatch - potential DNS rebinding attack", "SNI hostname not in allowed list"
- Log SNI extraction failures at DEBUG level (non-TLS traffic may not have SNI)
- **Never log**: passwords, tokens, auth headers, private keys
- Configurable log level via `LOG_LEVEL` environment variable (DEBUG, INFO, WARN, ERROR)

**Metrics Exposure**:
- Prometheus `/metrics` endpoint on port 9090
- Include labels: `identity`, `destination`, `status` where applicable
- Update metrics atomically to avoid partial reads
- Track both success and failure paths (denied, auth_required, etc.)

### Environment Variables
- `PROXY_PORT`: Proxy listener port (default: 4750)
- `METRICS_PORT`: Health/metrics listener port (default: 9090)
- `CONFIGMAP_PATH`: Path to config file (default: /etc/config/egress-policy.yaml)
- `WATCH_INTERVAL`: Config watch interval in seconds (default: 5)
- `LOG_LEVEL`: Logging level (default: INFO)

## Implementation Guidelines

### Matching Logic
**API Key Matching**:
1. Search all identities for an exact match of the provided API key
2. Return 407 Proxy Authentication Required if no match found
3. API keys must be unique across all identities (enforced at config load time)

**Destination Matching (priority order)**:
1. Exact domain match (case-insensitive: `api.example.com`)
2. Suffix wildcard match (case-insensitive: `*.example.com` matches `api.example.com`, `v2.api.example.com`)
3. CIDR or exact IP match (for IP-based destinations: `10.0.0.0/24`, `192.168.1.1`)
4. Return 403 if no match found

**Important**: SNI hostname must also match an allowed destination (see SNI Validation below)

### Error Handling
- Validate all inputs (identities, destinations)
- Handle network errors gracefully
- Don't crash on malformed config (log and continue with last known good config, increment `egress_proxy_config_load_errors_total`)
- Return appropriate HTTP status codes
- Timeout long-running operations (use context.WithTimeout)

**Config Reload Behavior**:
- Periodically check ConfigMap file for changes (via modification time or content hash)
- Reload only if file has changed
- Parse new config before applying (validate format and structure)
- If parse fails: log error, increment error counter, keep serving with previous config
- If parse succeeds: atomically swap config (use lock or atomic reference)
- In-flight requests continue with config version they started with (read config once per request)

### Security
- Validate proxy requests thoroughly (no null bytes, reasonable length limits)
- SNI + CONNECT destination validation (prevent DNS rebinding attacks)
- Sanitize logging output (never log passwords, auth headers, or sensitive headers)
- Use context timeouts to prevent hanging connections (e.g., 30s for tunnel setup)
- Close idle tunnels after timeout
- Rate limiting per identity (implementation optional, but consider for production)

### Concurrency & Performance
- Spawn one goroutine per CONNECT request (standard proxy pattern)
- Protect config reloads with sync.RWMutex or sync.Mutex
- Use atomic operations for metrics counters when possible
- Read config once per request (snapshot approach)
- Use buffered channels for config change notifications (optional)
