package proxy

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	"github.com/rtoma/k8s-egress-guard/internal/metrics"
)

// extractAPIKey extracts and validates the API key from Proxy-Authorization header
// Returns the extracted API key, or empty string if invalid/missing
func (s *Server) extractAPIKey(req *http.Request) string {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return ""
	}

	// Parse "Basic <base64>" format
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}

	encoded := strings.TrimPrefix(auth, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	// Extract username from "username:password"
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) == 0 {
		return ""
	}

	apiKey := parts[0]

	// Validate API key format: only alphanumeric, hyphens, dots, underscores
	// This prevents injection attacks and suspicious input
	if !isValidAPIKeyFormat(apiKey) {
		s.logger.Warn("invalid api_key format in auth header", map[string]any{
			"action": "denied",
		})
		return ""
	}

	return apiKey
}

// isValidAPIKeyFormat validates that an API key contains only safe characters
// Allows: alphanumeric, hyphens (-), dots (.), and underscores (_)
func isValidAPIKeyFormat(apiKey string) bool {
	if apiKey == "" || len(apiKey) > 256 {
		return false
	}

	for _, ch := range apiKey {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_') {
			return false
		}
	}

	return true
}

// validateRequest validates a CONNECT request and returns the validated request details
// Returns (*ValidatedRequest, statusCode, statusMessage) - if ValidatedRequest is nil, an error occurred
func (s *Server) validateRequest(req *http.Request) (*ValidatedRequest, int, string) {
	// Extract API key from Proxy-Authorization header
	apiKey := s.extractAPIKey(req)
	if apiKey == "" {
		s.logger.Warn("missing or invalid api_key in auth header", map[string]any{
			"received_api_key": apiKey,
			"action":           "denied",
		})
		metrics.RecordRequest(UnauthenticatedIdentityLabel, req.Host, "auth_required")
		return nil, http.StatusProxyAuthRequired, "Proxy authentication required"
	}

	// Parse host and port
	host, port := s.parseHostPort(req.Host)
	if host == "" {
		s.logger.Warn("invalid host/port in request", map[string]any{
			"received_host": req.Host,
			"action":        "denied",
		})
		metrics.RecordRequest(UnauthenticatedIdentityLabel, req.Host, "bad_request")
		return nil, http.StatusBadRequest, "Invalid host"
	}

	// Match API key in config to find identity
	identityName, found := s.config.MatchAPIKey(apiKey)
	if !found {
		s.logger.Warn("api_key not found in config", map[string]any{
			"received_api_key": apiKey,
			"received_host":    req.Host,
			"action":           "denied",
		})
		metrics.RecordRequest(UnauthenticatedIdentityLabel, host, "auth_required")
		return nil, http.StatusProxyAuthRequired, "API key not authorized"
	}

	// Check if destination is allowed
	if !s.config.IsDestinationAllowed(identityName, host) {
		s.logger.Warn("destination not allowed for identity", map[string]any{
			"identity":      identityName,
			"received_host": req.Host,
			"action":        "denied",
		})
		metrics.RecordRequest(identityName, host, "denied")
		return nil, http.StatusForbidden, "Destination not allowed"
	}

	return &ValidatedRequest{
		ReceivedAPIKey: apiKey,
		Host:           host,
		Port:           port,
		IdentityKey:    identityName,
	}, 0, ""
}

// parseHostPort parses host and port from the request host
func (s *Server) parseHostPort(hostPort string) (string, string) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		// If no port specified, assume 443
		return hostPort, "443"
	}
	return host, port
}
