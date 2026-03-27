package proxy

import (
	"io"

	"github.com/rtoma/k8s-egress-guard/internal/metrics"
)

const (
	DirectionEgress  = "egress"  // client to destination
	DirectionIngress = "ingress" // destination to client
	FlushEveryNBytes = 1000      // flush metrics every N bytes
)

// bytesCountingWriter wraps an io.Writer and tracks bytes written, updating metrics periodically
type bytesCountingWriter struct {
	writer            io.Writer
	identityKey       string
	destination       string
	direction         string
	bytesWritten      int64
	lastMetricsUpdate int64
}

// newBytesCountingWriter creates a new bytes counting writer
func newBytesCountingWriter(writer io.Writer, identityKey, destination, direction string) *bytesCountingWriter {
	return &bytesCountingWriter{
		writer:      writer,
		identityKey: identityKey,
		destination: destination,
		direction:   direction,
	}
}

// Write implements io.Writer and tracks bytes written
func (b *bytesCountingWriter) Write(p []byte) (n int, err error) {
	n, err = b.writer.Write(p)
	b.bytesWritten += int64(n)

	// Update metrics periodically (every N bytes)
	if b.bytesWritten-b.lastMetricsUpdate >= FlushEveryNBytes {
		metrics.RecordBytesTransferred(b.identityKey, b.destination, b.direction, b.bytesWritten-b.lastMetricsUpdate)
		b.lastMetricsUpdate = b.bytesWritten
	}

	return n, err
}

// flush updates metrics with any remaining bytes not yet reported
func (b *bytesCountingWriter) flush() {
	remaining := b.bytesWritten - b.lastMetricsUpdate
	if remaining > 0 {
		metrics.RecordBytesTransferred(b.identityKey, b.destination, b.direction, remaining)
		b.lastMetricsUpdate = b.bytesWritten
	}
}
