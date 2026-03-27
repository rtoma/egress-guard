package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rtoma/k8s-egress-guard/internal/config"
	"github.com/rtoma/k8s-egress-guard/internal/logging"
	"github.com/rtoma/k8s-egress-guard/internal/metrics"
)

const (
	UnauthenticatedIdentityLabel = "$unauth"
)

// ValidatedRequest represents a validated CONNECT proxy request
type ValidatedRequest struct {
	ReceivedAPIKey string // already sanitized, but it's still the raw received identity including whatever random suffix
	Host           string
	Port           string
	IdentityKey    string
}

// func (vr *ValidatedRequest) maskedAPIKey() string {
// 	k := vr.ReceivedAPIKey
// 	if len(k) <= 6 {
// 		return "***"
// 	}
// 	return k[:3] + "***" + k[len(k)-3:]
// }

// LogFields returns standardized fields with optional additional key-value pairs
// Usage: validReq.LogFields("destination", destAddr, "error", err)
func (vr *ValidatedRequest) LogFields(pairs ...any) map[string]any {
	fields := map[string]any{
		"identity": vr.IdentityKey,
		// "api_key":  vr.maskedAPIKey(),
	}

	// Add arbitrary key-value pairs
	for i := 0; i < len(pairs); i += 2 {
		if i+1 < len(pairs) {
			if key, ok := pairs[i].(string); ok {
				fields[key] = pairs[i+1]
			}
		}
	}
	return fields
}

// Server is the HTTP CONNECT proxy server
type Server struct {
	config      *config.Provider
	logger      *logging.Logger
	listener    net.Listener
	port        string
	httpServer  *http.Server
	activeConns int32 // atomic counter for active connections
}

// NewServer creates a new proxy server
func NewServer(cfg *config.Provider, logger *logging.Logger, port string) *Server {
	return &Server{
		config: cfg,
		logger: logger,
		port:   port,
	}
}

// Start starts the proxy server using http.Server with CONNECT handler
func (s *Server) Start() error {
	// Create listener first so we can capture the actual address (needed for port 0)
	// For port 0, explicitly use 127.0.0.1 to ensure IPv4 and avoid IPv6 issues
	addr := ":" + s.port
	if s.port == "0" {
		addr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = listener

	// Create HTTP server with our CONNECT handler
	server := &http.Server{
		Handler:        http.HandlerFunc(s.handleHTTP),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				atomic.AddInt32(&s.activeConns, 1)
			case http.StateHijacked, http.StateClosed:
				atomic.AddInt32(&s.activeConns, -1)
			}
		},
	}
	s.httpServer = server

	s.logger.Info("proxy server started", map[string]any{
		"address": s.listener.Addr().String(),
	})

	err = server.Serve(listener)
	// During graceful shutdown, Serve returns http.ErrServerClosed or net.ErrClosed
	// Both are expected, so don't propagate them as errors
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Stop gracefully stops the proxy server, waiting for in-flight requests to complete
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}

	// Log current in-flight connections before shutdown
	active := atomic.LoadInt32(&s.activeConns)
	if active > 0 {
		s.logger.Info("graceful shutdown initiated", map[string]any{
			"in_flight_connections": active,
			"message":               "waiting for active connections to complete",
		})
	} else {
		s.logger.Info("graceful shutdown initiated", map[string]any{
			"in_flight_connections": 0,
		})
	}

	// Gracefully shutdown - stops accepting new connections and waits for active ones
	err := s.httpServer.Shutdown(ctx)

	// Log final state after shutdown
	remaining := atomic.LoadInt32(&s.activeConns)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.logger.Warn("shutdown timeout reached", map[string]any{
				"remaining_connections": remaining,
				"message":               "forced close of remaining connections",
			})
		}
		return err
	}

	if active > 0 {
		s.logger.Info("all in-flight connections completed", map[string]any{
			"completed_connections": active,
		})
	}

	return nil
}

// Listener returns the underlying network listener (for testing)
func (s *Server) Listener() net.Listener {
	return s.listener
}

// handleHTTP is the HTTP handler for the proxy server (called by http.Server)
// It hijacks the connection and processes the CONNECT request
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Only handle CONNECT method
	if r.Method != http.MethodConnect {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the request and extract identity, host, port
	validReq, statusCode, statusMsg := s.validateRequest(r)
	if validReq == nil {
		http.Error(w, statusMsg, statusCode)
		return
	}

	// Hijack the connection to take full control
	// IMPORTANT: Hijack returns a bufio.ReadWriter with any data already buffered during
	// HTTP request parsing. The client may have sent additional bytes (like TLS ClientHello)
	// immediately after the CONNECT request, and these bytes are now in readWriter.Reader's buffer.
	// However, readWriter.Reader's internal connReader panics if used after hijack, so we must
	// extract buffered data into a byte slice before using it.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Error("response writer does not support hijacking", validReq.LogFields())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	clientConn, readWriter, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("failed to hijack connection", validReq.LogFields("error", err))
		return
	}
	defer clientConn.Close()

	// Now that we've hijacked, we manage the connection timeline
	// Remove any read deadline that was set for HTTP parsing
	clientConn.SetReadDeadline(time.Time{})

	// Connect to destination
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	destAddr := net.JoinHostPort(validReq.Host, validReq.Port)
	dialer := &net.Dialer{}
	destConn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		s.logger.Error("failed to connect to destination", validReq.LogFields("destination", destAddr, "error", err))
		s.sendRawResponse(clientConn, http.StatusBadGateway, "Failed to connect to destination")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "connection_failed")
		return
	}
	defer destConn.Close()

	// Send 200 Connection Established (raw socket)
	s.sendRawResponse(clientConn, http.StatusOK, "Connection established")

	// TLS-Only Proxy: Wait for and validate TLS ClientHello with SNI
	// This is done AFTER sending 200 OK, as clients send ClientHello after receiving it
	sniValidated, tlsData, err := s.validateTLSAndSNI(clientConn, readWriter, validReq)
	if err != nil {
		// Validation failed - error response already sent, just return
		return
	}

	if sniValidated {
		// Log successful SNI validation
		s.logger.Info("proxy request allowed", validReq.LogFields("destination", validReq.Host))
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "allowed")
	} else {
		// This shouldn't happen as validateTLSAndSNI returns error if validation fails
		s.logger.Error("unexpected state: SNI not validated but no error", validReq.LogFields())
		s.sendRawResponse(clientConn, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Start tunneling - all validation is complete
	// startTime := time.Now()
	s.tunnel(tlsData, clientConn, destConn, validReq.IdentityKey, validReq.Host)
	// duration := time.Since(startTime).Seconds()
	// metrics.RecordRequestDuration(validReq.IdentityKey, validReq.Host, duration)
}
