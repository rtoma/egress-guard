package config

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Identity represents an identity group with its API keys and allowed destinations
type Identity struct {
	APIKeys             []string `yaml:"api_keys"`
	AllowedDestinations []string `yaml:"allowed_destinations"`
}

// Config represents the egress policy configuration
type Config struct {
	Identities map[string]Identity `yaml:"identities"`
}

// Provider manages configuration loading and hot reloading
type Provider struct {
	mu            sync.RWMutex
	config        *Config
	configPath    string
	lastModTime   time.Time
	watchInterval time.Duration
	stopCh        chan struct{}
	reloadCh      chan ReloadResult
}

// NewProvider creates a new configuration provider
func NewProvider(configPath string, watchInterval time.Duration) (*Provider, error) {
	p := &Provider{
		configPath:    configPath,
		watchInterval: watchInterval,
		stopCh:        make(chan struct{}),
		reloadCh:      make(chan ReloadResult, 1),
	}

	// Load initial configuration
	if err := p.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load initial config: %w", err)
	}

	// Capture the initial file modification time to avoid spurious reloads
	info, err := os.Stat(configPath)
	if err == nil {
		p.lastModTime = info.ModTime()
	}

	return p, nil
}

// loadConfig loads and parses the configuration file
func (p *Provider) loadConfig() error {
	data, err := os.ReadFile(p.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate config
	if err := p.validateConfig(&cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	p.mu.Lock()
	p.config = &cfg
	p.mu.Unlock()

	return nil
}

// validateConfig validates the configuration structure
func (p *Provider) validateConfig(cfg *Config) error {
	if cfg.Identities == nil {
		return fmt.Errorf("identities map is nil")
	}

	// Track API keys to detect duplicates
	seenAPIKeys := make(map[string]string) // apiKey -> identityName

	for identityName, identity := range cfg.Identities {
		if identityName == "" {
			return fmt.Errorf("empty identity name")
		}

		// Validate api_keys
		if len(identity.APIKeys) == 0 {
			return fmt.Errorf("no api_keys for identity %s", identityName)
		}
		if slices.Contains(identity.APIKeys, "") {
			return fmt.Errorf("empty api_key for identity %s", identityName)
		}

		// Check for duplicate API keys across identities
		for _, apiKey := range identity.APIKeys {
			if existingIdentity, exists := seenAPIKeys[apiKey]; exists {
				return fmt.Errorf("duplicate api_key %q found in identities %q and %q", apiKey, existingIdentity, identityName)
			}
			seenAPIKeys[apiKey] = identityName
		}

		// Validate allowed_destinations
		if len(identity.AllowedDestinations) == 0 {
			return fmt.Errorf("no allowed_destinations for identity %s", identityName)
		}
		if slices.Contains(identity.AllowedDestinations, "") {
			return fmt.Errorf("empty destination for identity %s", identityName)
		}
	}

	return nil
}

// GetConfig returns the current configuration (thread-safe)
func (p *Provider) GetConfig() *Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// Stop stops the config watcher
func (p *Provider) Stop() {
	close(p.stopCh)
}

// MatchAPIKey finds the identity that owns the given API key
// Returns the identity name and true if found, empty string and false otherwise
func (p *Provider) MatchAPIKey(apiKey string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Search all identities for an exact match of the API key
	for identityName, identity := range p.config.Identities {
		if slices.Contains(identity.APIKeys, apiKey) {
			return identityName, true
		}
	}

	return "", false
}

// IsDestinationAllowed checks if the destination is allowed for the given identity
func (p *Provider) IsDestinationAllowed(identityName, destination string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	identity, exists := p.config.Identities[identityName]
	if !exists {
		return false
	}

	// Normalize destination (lowercase for domain matching)
	destination = strings.ToLower(destination)

	for _, allowed := range identity.AllowedDestinations {
		allowed = strings.ToLower(allowed)

		// 1. Exact match
		if allowed == destination {
			return true
		}

		// 2. Suffix wildcard match (*.example.com)
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(destination, suffix) {
				return true
			}
		}

		// 3. CIDR or IP match
		if matchIPDestination(allowed, destination) {
			return true
		}
	}

	return false
}

// matchIPDestination checks if destination matches an IP address or CIDR range
func matchIPDestination(allowed, destination string) bool {
	// Try CIDR match first
	_, network, err := net.ParseCIDR(allowed)
	if err == nil {
		ip := net.ParseIP(destination)
		if ip != nil {
			return network.Contains(ip)
		}
	}

	// Try exact IP match
	allowedIP := net.ParseIP(allowed)
	if allowedIP != nil {
		destIP := net.ParseIP(destination)
		if destIP != nil {
			return allowedIP.Equal(destIP)
		}
	}

	return false
}

// GetIdentityCount returns the number of identities in the config
func (p *Provider) GetIdentityCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.config.Identities)
}

// GetDestinationsForIdentity returns the list of allowed destinations for an identity
func (p *Provider) GetDestinationsForIdentity(identityName string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	identity, exists := p.config.Identities[identityName]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	result := make([]string, len(identity.AllowedDestinations))
	copy(result, identity.AllowedDestinations)
	return result
}
