package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Level represents the logging level
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a log level from string
func ParseLevel(s string) Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN":
		return WARN
	case "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// Logger is a structured JSON logger
type Logger struct {
	level  Level
	output io.Writer
}

// NewLogger creates a new logger
func NewLogger(level Level) *Logger {
	return &Logger{
		level:  level,
		output: os.Stdout,
	}
}

// Entry represents a log entry
type Entry struct {
	Timestamp   string         `json:"timestamp"`
	Level       string         `json:"level"`
	Message     string         `json:"message"`
	Identity    string         `json:"identity,omitempty"`
	Destination string         `json:"destination,omitempty"`
	Action      string         `json:"action,omitempty"`
	Error       string         `json:"error,omitempty"`
	Fields      map[string]any `json:"fields,omitempty"`
}

// extractStringField extracts a string value from fields map and removes it
func extractStringField(fields map[string]any, key string) string {
	if v, ok := fields[key]; ok {
		if s, ok := v.(string); ok {
			delete(fields, key)
			return s
		}
	}
	return ""
}

// extractErrorField extracts an error field (as string) from fields map and removes it
func extractErrorField(fields map[string]any) string {
	if v, ok := fields["error"]; ok {
		delete(fields, "error")
		if err, ok := v.(error); ok {
			return err.Error()
		} else if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// log writes a log entry
func (l *Logger) log(level Level, msg string, fields map[string]any) {
	if level < l.level {
		return
	}

	ts := time.Now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	entry := Entry{
		Timestamp:   ts,
		Level:       level.String(),
		Message:     msg,
		Identity:    extractStringField(fields, "identity"),
		Destination: extractStringField(fields, "destination"),
		Action:      extractStringField(fields, "action"),
		Error:       extractErrorField(fields),
	}

	// Remaining fields
	if len(fields) > 0 {
		entry.Fields = fields
	}

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal log entry: %v\n", err)
		return
	}

	l.output.Write(data)
	l.output.Write([]byte("\n"))
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields map[string]any) {
	l.log(DEBUG, msg, fields)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields map[string]any) {
	l.log(INFO, msg, fields)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields map[string]any) {
	l.log(WARN, msg, fields)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields map[string]any) {
	l.log(ERROR, msg, fields)
}

// Helper methods for common logging patterns

// LogProxyRequest logs a proxy request
func (l *Logger) LogProxyRequest(identity, destination, action string, allowed bool) {
	status := "allowed"
	if !allowed {
		status = "denied"
	}
	l.Info("proxy request", map[string]any{
		"identity":    identity,
		"destination": destination,
		"action":      action,
		"status":      status,
	})
}

// LogConfigReload logs a config reload event
func (l *Logger) LogConfigReload(success bool, identityCount int, err error) {
	fields := map[string]any{
		"action":         "config_reload",
		"success":        success,
		"identity_count": identityCount,
	}
	if err != nil {
		fields["error"] = err
		l.Error("config reload failed", fields)
	} else {
		l.Info("config reloaded", fields)
	}
}

// LogSNIMismatch logs an SNI hostname mismatch
func (l *Logger) LogSNIMismatch(identity, connectDest, sniHost string) {
	l.Warn("SNI hostname mismatch", map[string]any{
		"identity":     identity,
		"destination":  connectDest,
		"sni_hostname": sniHost,
		"action":       "denied",
	})
}
