package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rtoma/egress-guard/internal/config"
	"github.com/rtoma/egress-guard/internal/logging"
	"github.com/rtoma/egress-guard/internal/metrics"
	"github.com/rtoma/egress-guard/internal/proxy"
)

const (
	defaultProxyPort   = "4750"
	defaultMetricsPort = "9090"
	defaultConfigPath  = "/etc/config/egress-policy.yaml"
	defaultLogLevel    = "INFO"
)

func main() {
	// Get configuration from environment
	proxyPort := getEnv("PROXY_PORT", defaultProxyPort)
	metricsPort := getEnv("METRICS_PORT", defaultMetricsPort)
	configPath := getEnv("CONFIGMAP_PATH", defaultConfigPath)
	watchIntervalSec := getEnvInt("WATCH_INTERVAL", 5)
	logLevelStr := getEnv("LOG_LEVEL", defaultLogLevel)

	// Initialize logger
	logLevel := logging.ParseLevel(logLevelStr)
	logger := logging.NewLogger(logLevel)

	logger.Info("starting k8s-egress-guard", map[string]any{
		"proxy_port":     proxyPort,
		"metrics_port":   metricsPort,
		"config_path":    configPath,
		"watch_interval": watchIntervalSec,
		"log_level":      logLevelStr,
	})

	// Load configuration
	watchInterval := time.Duration(watchIntervalSec) * time.Second
	cfg, err := config.NewProvider(configPath, watchInterval)
	if err != nil {
		logger.Error("failed to load config", map[string]any{
			"error": err,
		})
		os.Exit(1)
	}

	// Update metrics with initial config
	updateConfigMetrics(cfg)

	// Start config watcher
	go func() {
		cfg.Watch()
	}()

	// Watch for config reloads
	go func() {
		for result := range cfg.ReloadChannel() {
			if result.Success {
				logger.LogConfigReload(true, result.IdentityCount, nil)
				metrics.RecordConfigReload()
				updateConfigMetrics(cfg)
			} else {
				logger.LogConfigReload(false, result.IdentityCount, result.Error)
				metrics.RecordConfigLoadError()
			}
		}
	}()

	// Start metrics server
	metricsServer := startMetricsServer(metricsPort, logger)

	// Start proxy server
	proxyServer := proxy.NewServer(cfg, logger, proxyPort)
	go func() {
		if err := proxyServer.Start(); err != nil {
			logger.Error("proxy server error", map[string]any{
				"error": err,
			})
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down", map[string]any{})

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdownServers(ctx, logger, metricsServer, proxyServer)
	cfg.Stop()
	logger.Info("shutdown complete", map[string]any{})
}

// shutdownServers gracefully shuts down all servers
func shutdownServers(ctx context.Context, logger *logging.Logger, metricsServer *http.Server, proxyServer *proxy.Server) {
	if err := metricsServer.Shutdown(ctx); err != nil {
		logger.Error("metrics server shutdown error", map[string]any{
			"error": err,
		})
	} else {
		logger.Info("metrics server shut down", map[string]any{})
	}

	if err := proxyServer.Stop(ctx); err != nil {
		logger.Error("proxy server shutdown error", map[string]any{
			"error": err,
		})
	} else {
		logger.Info("proxy server shut down", map[string]any{})
	}
}

// startMetricsServer starts the health and metrics HTTP server
func startMetricsServer(port string, logger *logging.Logger) *http.Server {
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		logger.Info("metrics server started", map[string]any{
			"port": port,
		})
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", map[string]any{
				"error": err,
			})
		}
	}()

	return server
}

// updateConfigMetrics updates Prometheus metrics based on current config
func updateConfigMetrics(cfg *config.Provider) {
	// Clear existing gauges
	metrics.ClearAllowedDestinations()

	// Get snapshot of current config
	currentConfig := cfg.GetConfig()
	if currentConfig == nil {
		return
	}

	// Update gauge for each identity
	for identity := range currentConfig.Identities {
		destinations := cfg.GetDestinationsForIdentity(identity)
		metrics.UpdateAllowedDestinations(identity, len(destinations))
	}
}

// getEnv returns environment variable value or default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns environment variable as int or default
func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}
