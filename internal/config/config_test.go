package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewProvider(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `identities:
  frontend-services:
    api_keys: ["frontend-1", "frontend-2"]
    allowed_destinations: ["api.example.com", "*.cdn.example.com"]
  backend-services:
    api_keys: ["backend-1"]
    allowed_destinations: ["db.internal", "*.amazonaws.com"]
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider, err := NewProvider(configPath, 1*time.Second)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Stop()

	if provider.GetIdentityCount() != 2 {
		t.Errorf("expected 2 identities, got %d", provider.GetIdentityCount())
	}
}

func TestMatchAPIKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `identities:
  frontend-services:
    api_keys: ["frontend-1", "frontend-2"]
    allowed_destinations: ["api.example.com"]
  backend-services:
    api_keys: ["backend-1", "backend-2"]
    allowed_destinations: ["db.internal"]
  monitoring-services:
    api_keys: ["prometheus"]
    allowed_destinations: ["prometheus.internal"]
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider, err := NewProvider(configPath, 1*time.Second)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Stop()

	tests := []struct {
		name         string
		apiKey       string
		wantIdentity string
		wantMatched  bool
	}{
		{"exact match frontend-1", "frontend-1", "frontend-services", true},
		{"exact match frontend-2", "frontend-2", "frontend-services", true},
		{"exact match backend-1", "backend-1", "backend-services", true},
		{"exact match prometheus", "prometheus", "monitoring-services", true},
		{"no match unknown-key", "unknown-key", "", false},
		{"no match partial", "frontend", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, matched := provider.MatchAPIKey(tt.apiKey)
			if matched != tt.wantMatched {
				t.Errorf("MatchAPIKey(%q) matched = %v, want %v", tt.apiKey, matched, tt.wantMatched)
			}
			if identity != tt.wantIdentity {
				t.Errorf("MatchAPIKey(%q) identity = %q, want %q", tt.apiKey, identity, tt.wantIdentity)
			}
		})
	}
}

func TestIsDestinationAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `identities:
  frontend-services:
    api_keys: ["frontend-1"]
    allowed_destinations: ["api.example.com", "*.cdn.example.com", "192.168.1.1", "10.0.0.0/24"]
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	provider, err := NewProvider(configPath, 1*time.Second)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}
	defer provider.Stop()

	tests := []struct {
		name        string
		destination string
		want        bool
	}{
		{"exact domain match", "api.example.com", true},
		{"exact domain case insensitive", "API.EXAMPLE.COM", true},
		{"wildcard suffix match", "v1.cdn.example.com", true},
		{"wildcard suffix match 2", "v2.api.cdn.example.com", true},
		{"exact IP match", "192.168.1.1", true},
		{"CIDR match", "10.0.0.5", true},
		{"CIDR match 2", "10.0.0.255", true},
		{"no match domain", "evil.com", false},
		{"no match IP", "192.168.1.2", false},
		{"no match CIDR", "10.0.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := provider.IsDestinationAllowed("frontend-services", tt.destination)
			if allowed != tt.want {
				t.Errorf("IsDestinationAllowed(%q) = %v, want %v", tt.destination, allowed, tt.want)
			}
		})
	}
}

func TestDuplicateAPIKeyDetection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Config with duplicate api_key across identities
	configData := `identities:
  frontend-services:
    api_keys: ["shared-key"]
    allowed_destinations: ["api.example.com"]
  backend-services:
    api_keys: ["shared-key"]
    allowed_destinations: ["db.internal"]
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := NewProvider(configPath, 1*time.Second)
	if err == nil {
		t.Errorf("expected error for duplicate api_key, but got none")
	}
}

func TestEmptyAPIKeysRejected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Config with empty api_keys list
	configData := `identities:
  frontend-services:
    api_keys: []
    allowed_destinations: ["api.example.com"]
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := NewProvider(configPath, 1*time.Second)
	if err == nil {
		t.Errorf("expected error for empty api_keys, but got none")
	}
}
