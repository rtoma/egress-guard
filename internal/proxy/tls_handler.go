package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rtoma/egress-guard/internal/metrics"
)

// isIPAddress checks if the given host is an IP address (v4 or v6)
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// normalizeHostForComparison compares two hostnames for equality (case-insensitive)
// Returns true if they match, false otherwise
func (s *Server) normalizeHostForComparison(host1, host2 string) bool {
	return strings.EqualFold(host1, host2)
}

// validateSNI validates the SNI hostname against CONNECT destination and allowed destinations
// Returns true if validation passes, false otherwise
func (s *Server) validateSNI(validReq *ValidatedRequest, sniHost string) bool {
	// Validate 1: SNI hostname must match CONNECT destination (DNS rebinding check)
	if !s.normalizeHostForComparison(sniHost, validReq.Host) {
		s.logger.Warn("SNI hostname mismatch - potential DNS rebinding attack", validReq.LogFields(
			"connect_dest", validReq.Host,
			"sni_hostname", sniHost,
		))
		return false
	}

	// Validate 2: SNI hostname must be in allowed destinations
	if !s.config.IsDestinationAllowed(validReq.IdentityKey, sniHost) {
		s.logger.Warn("SNI hostname not in allowed list", validReq.LogFields(
			"connect_dest", validReq.Host,
			"sni_hostname", sniHost,
		))
		return false
	}

	return true
}

// validateTLSAndSNI waits for TLS ClientHello, extracts SNI, and validates it
// Returns (sniValidated, tlsData, error)
// If error is not nil, an error response has already been sent to the client
func (s *Server) validateTLSAndSNI(clientConn net.Conn, readWriter *bufio.ReadWriter, validReq *ValidatedRequest) (bool, []byte, error) {
	// First, extract any buffered data from readWriter.Reader
	// After hijack, readWriter.Reader's internal connReader is marked as hijacked
	// and will panic if we try to read from it directly. We must read buffered data
	// into a byte slice first.
	var bufferedData []byte
	if readWriter.Reader.Buffered() > 0 {
		bufferedData = make([]byte, readWriter.Reader.Buffered())
		_, err := io.ReadFull(readWriter.Reader, bufferedData)
		if err != nil {
			s.logger.Error("failed to read buffered data", validReq.LogFields("error", err))
			s.sendRawResponse(clientConn, http.StatusInternalServerError, "Failed to read buffered data")
			metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "internal_error")
			return false, nil, fmt.Errorf("failed to read buffered data: %w", err)
		}
	}

	// Check if we already have TLS data in buffer
	if len(bufferedData) > 0 {
		sniHost := parseSNI(bufferedData)
		if sniHost != "" {
			// SNI found in buffered data - validate it
			if !s.validateSNI(validReq, sniHost) {
				s.sendRawResponse(clientConn, http.StatusForbidden, "SNI validation failed")
				metrics.RecordSNIValidationFailure(validReq.IdentityKey, validReq.Host)
				return false, nil, fmt.Errorf("SNI validation failed")
			}
			// SNI validation passed
			s.logger.Debug("SNI validated successfully (buffered data)", validReq.LogFields("sni_hostname", sniHost))
			metrics.RecordSNIValid(validReq.IdentityKey, validReq.Host)
			return true, bufferedData, nil
		}
		// Buffered data present but no SNI - could be incomplete TLS handshake
		// Fall through to wait for more data
	}

	// Wait for TLS ClientHello with timeout
	// Set a 5-second deadline for TLS handshake to start
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer clientConn.SetReadDeadline(time.Time{}) // Clear deadline after

	s.logger.Debug("waiting for TLS ClientHello", validReq.LogFields("buffered_bytes", len(bufferedData)))

	// Create a new reader to peek at incoming data
	// Combine any buffered data with the connection
	var reader *bufio.Reader
	if len(bufferedData) > 0 {
		reader = bufio.NewReader(io.MultiReader(bytes.NewReader(bufferedData), clientConn))
	} else {
		reader = bufio.NewReader(clientConn)
	}

	// First, peek at TLS record header (5 bytes) to determine record length
	// This avoids blocking on Peek() with a large size when less data is available
	headerData, err := reader.Peek(5)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.logger.Warn("timeout waiting for TLS record header", validReq.LogFields("destination", validReq.Host))
			s.sendRawResponse(clientConn, http.StatusRequestTimeout, "Request timeout")
			metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "timeout")
			return false, nil, fmt.Errorf("timeout waiting for TLS record header")
		}
		s.logger.Error("failed to peek TLS record header", validReq.LogFields("error", err))
		s.sendRawResponse(clientConn, http.StatusBadRequest, "Failed to read TLS data")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "bad_request")
		return false, nil, fmt.Errorf("failed to peek TLS header: %w", err)
	}

	s.logger.Debug("received TLS record header", validReq.LogFields("header_len", strconv.Itoa(len(headerData)), "first_byte", fmt.Sprintf("0x%02x", headerData[0])))

	// Verify this is TLS traffic (first byte must be 0x16 for TLS handshake)
	if headerData[0] != 0x16 {
		s.logger.Warn("non-TLS traffic detected", validReq.LogFields("destination", validReq.Host, "first_byte", fmt.Sprintf("0x%02x", headerData[0])))
		s.sendRawResponse(clientConn, http.StatusBadRequest, "Only HTTPS connections allowed")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "non_tls")
		return false, nil, fmt.Errorf("non-TLS traffic")
	}

	// Extract TLS record length from header (bytes 3-4, big-endian)
	recordLen := int(headerData[3])<<8 | int(headerData[4])
	totalLen := 5 + recordLen // TLS record header (5 bytes) + payload

	s.logger.Debug("TLS record details", validReq.LogFields(
		"record_len", strconv.Itoa(recordLen),
		"total_bytes", strconv.Itoa(totalLen),
	))

	// Sanity check: TLS record should be reasonable size (typically < 16KB)
	if totalLen > 16384 {
		s.logger.Warn("TLS record too large", validReq.LogFields("destination", validReq.Host, "total_bytes", totalLen))
		s.sendRawResponse(clientConn, http.StatusBadRequest, "Invalid TLS record size")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "bad_request")
		return false, nil, fmt.Errorf("TLS record too large: %d bytes", totalLen)
	}

	// Now peek exactly the amount needed for the complete TLS record
	tlsData, err := reader.Peek(totalLen)
	if err != nil && err != io.EOF {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.logger.Warn("timeout reading TLS record", validReq.LogFields("destination", validReq.Host, "expected_bytes", totalLen, "received_bytes", len(tlsData)))
			s.sendRawResponse(clientConn, http.StatusRequestTimeout, "Request timeout")
			metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "timeout")
			return false, nil, fmt.Errorf("timeout reading TLS record")
		}
		s.logger.Error("failed to read TLS record", validReq.LogFields("error", err))
		s.sendRawResponse(clientConn, http.StatusBadRequest, "Failed to read TLS data")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "bad_request")
		return false, nil, fmt.Errorf("failed to read TLS record: %w", err)
	}

	s.logger.Debug("received TLS record", validReq.LogFields(
		"received_bytes", strconv.Itoa(len(tlsData)),
	))

	// Check if destination is an IP address
	// IP addresses cannot have SNI (TLS limitation), so skip SNI validation
	if isIPAddress(validReq.Host) {
		s.logger.Debug("TLS connection to IP address, skipping SNI validation", validReq.LogFields(
			"destination", validReq.Host,
		))
		// IP address already validated against allowed destinations in CONNECT handler
		// Proceed directly to tunnel setup
		actualLen := len(tlsData)
		allTLSData := make([]byte, actualLen)
		_, err := io.ReadFull(reader, allTLSData)
		if err != nil {
			s.logger.Error("failed to consume peeked TLS data", validReq.LogFields("error", err))
			s.sendRawResponse(clientConn, http.StatusInternalServerError, "Failed to read TLS data")
			metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "internal_error")
			return false, nil, fmt.Errorf("failed to consume peeked data: %w", err)
		}
		return true, allTLSData, nil
	}

	// Extract SNI from TLS ClientHello (required for hostname destinations)
	sniHost := parseSNI(tlsData)
	if sniHost == "" {
		s.logger.Warn("TLS ClientHello without SNI extension", validReq.LogFields("destination", validReq.Host, "tls_data_bytes", len(tlsData)))
		s.sendRawResponse(clientConn, http.StatusForbidden, "SNI extension required for hostname destinations")
		metrics.RecordSNINotExtracted()
		return false, nil, fmt.Errorf("SNI extension required")
	}

	s.logger.Debug("SNI extracted from ClientHello", validReq.LogFields(
		"sni_host", sniHost,
		"connect_host", validReq.Host,
	))

	// Validate SNI
	if !s.validateSNI(validReq, sniHost) {
		s.sendRawResponse(clientConn, http.StatusForbidden, "SNI validation failed")
		metrics.RecordSNIValidationFailure(validReq.IdentityKey, validReq.Host)
		return false, nil, fmt.Errorf("SNI validation failed")
	}

	// SNI validation passed - read all peeked data into a buffer
	actualLen := len(tlsData)
	allTLSData := make([]byte, actualLen)
	_, err = io.ReadFull(reader, allTLSData)
	if err != nil {
		s.logger.Error("failed to consume peeked TLS data", validReq.LogFields("error", err))
		s.sendRawResponse(clientConn, http.StatusInternalServerError, "Failed to read TLS data")
		metrics.RecordRequest(validReq.IdentityKey, validReq.Host, "internal_error")
		return false, nil, fmt.Errorf("failed to consume peeked data: %w", err)
	}

	s.logger.Debug("SNI validated successfully", validReq.LogFields("sni_hostname", sniHost)) // , "tls_bytes", len(allTLSData)))
	metrics.RecordSNIValid(validReq.IdentityKey, validReq.Host)

	return true, allTLSData, nil
}

// sendRawResponse sends an HTTP response to a hijacked connection (raw socket)
func (s *Server) sendRawResponse(conn net.Conn, statusCode int, message string) {
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = message
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", statusCode, statusText)
	_, err := conn.Write([]byte(response))
	if err != nil {
		s.logger.Error("failed to send response", map[string]any{
			"status_code": statusCode,
			"error":       err,
		})
	}
}

// parseSNI extracts SNI from TLS ClientHello bytes
func parseSNI(data []byte) string {
	// TLS Record: [type(1), version(2), length(2), handshake...]
	if len(data) < 5 {
		return ""
	}

	// Skip TLS record header (5 bytes)
	pos := 5

	// Handshake: [type(1), length(3), ...]
	if len(data) < pos+4 {
		return ""
	}

	handshakeType := data[pos]
	if handshakeType != 0x01 { // ClientHello = 0x01
		return ""
	}

	pos += 4 // Skip handshake header

	// ClientHello: [version(2), random(32), session_id_length(1), ...]
	if len(data) < pos+2+32+1 {
		return ""
	}

	pos += 2 + 32 // Skip version and random

	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suites: [length(2), suites...]
	if len(data) < pos+2 {
		return ""
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Compression methods: [length(1), methods...]
	if len(data) < pos+1 {
		return ""
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions: [length(2), extensions...]
	if len(data) < pos+2 {
		return ""
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	endPos := pos + extensionsLen
	if len(data) < endPos {
		return ""
	}

	// Parse extensions to find SNI (type 0x0000)
	for pos < endPos {
		if len(data) < pos+4 {
			break
		}

		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x0000 { // SNI extension
			if len(data) < pos+extLen {
				break
			}

			// SNI extension data: [list_length(2), name_type(1), name_length(2), name...]
			if extLen < 5 {
				break
			}

			nameType := data[pos+2]
			if nameType == 0x00 { // host_name
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				nameStart := pos + 5
				nameEnd := nameStart + nameLen

				if len(data) >= nameEnd {
					return string(data[nameStart:nameEnd])
				}
			}
			break
		}

		pos += extLen
	}

	return ""
}

// tunnel creates a bidirectional tunnel between client and destination
// bufferedData contains any data that was buffered during HTTP parsing
func (s *Server) tunnel(bufferedData []byte, clientConn net.Conn, destConn net.Conn, identityKey, destination string) {
	done := make(chan struct{}, 2)

	// Client -> Destination (egress)
	// Combine buffered data with raw connection using io.MultiReader
	go func() {
		var reader io.Reader
		if len(bufferedData) > 0 {
			// Read buffered data first, then continue with raw connection
			reader = io.MultiReader(bytes.NewReader(bufferedData), clientConn)
		} else {
			reader = clientConn
		}
		destWriter := newBytesCountingWriter(destConn, identityKey, destination, DirectionEgress)
		io.Copy(destWriter, reader)
		destWriter.flush()
		done <- struct{}{}
	}()

	// Destination -> Client (ingress)
	go func() {
		clientWriter := newBytesCountingWriter(clientConn, identityKey, destination, DirectionIngress)
		io.Copy(clientWriter, destConn)
		clientWriter.flush()
		done <- struct{}{}
	}()

	// Wait for both directions to finish
	// This prevents premature connection closure while one side is still copying
	<-done
	<-done
}
