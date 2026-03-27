package config

import (
	"os"
	"time"
)

// ReloadResult represents the outcome of a config reload attempt
type ReloadResult struct {
	Success       bool
	Error         error
	IdentityCount int
}

// Watch starts watching the config file for changes
func (p *Provider) Watch() {
	ticker := time.NewTicker(p.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.checkAndReload()
		case <-p.stopCh:
			return
		}
	}
}

// checkAndReload checks if the config file has changed and reloads if necessary
func (p *Provider) checkAndReload() {
	info, err := os.Stat(p.configPath)
	if err != nil {
		return // File might be temporarily unavailable
	}

	modTime := info.ModTime()
	if modTime.After(p.lastModTime) {
		p.lastModTime = modTime
		if err := p.loadConfig(); err != nil {
			// Send failure result
			select {
			case p.reloadCh <- ReloadResult{Success: false, Error: err, IdentityCount: p.GetIdentityCount()}:
			default:
			}
			return
		}
		// Send success result
		select {
		case p.reloadCh <- ReloadResult{Success: true, IdentityCount: p.GetIdentityCount()}:
		default:
		}
	}
}

// ReloadChannel returns a channel that signals config reload results
func (p *Provider) ReloadChannel() <-chan ReloadResult {
	return p.reloadCh
}
