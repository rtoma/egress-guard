package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestsTotal counts total proxy requests by identity, destination, and status
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "egress_proxy_requests_total",
			Help: "Total number of egress proxy requests",
		},
		[]string{"identity", "destination", "status"},
	)

	// // RequestDuration tracks request duration histogram
	// RequestDuration = promauto.NewHistogramVec(
	// 	prometheus.HistogramOpts{
	// 		Name:    "egress_proxy_request_duration_seconds",
	// 		Help:    "Duration of egress proxy requests in seconds",
	// 		Buckets: prometheus.DefBuckets,
	// 	},
	// 	[]string{"identity", "destination"},
	// )

	// ConfigReloadsTotal counts successful config reloads
	ConfigReloadsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "egress_proxy_config_reloads_total",
			Help: "Total number of successful config reloads",
		},
	)

	// ConfigLoadErrorsTotal counts config load errors
	ConfigLoadErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "egress_proxy_config_load_errors_total",
			Help: "Total number of config load errors",
		},
	)

	// AllowedDestinations tracks number of allowed destinations per identity
	AllowedDestinations = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "egress_proxy_allowed_destinations",
			Help: "Number of allowed destinations per identity",
		},
		[]string{"identity"},
	)

	// SNIMismatchTotal counts SNI hostname mismatches (DNS rebinding attempts)
	SNIMismatchTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "egress_proxy_sni_mismatch_total",
			Help: "Total number of SNI hostname mismatches (potential DNS rebinding attacks)",
		},
		[]string{"identity", "destination"},
	)

	// SNIValidTotal counts successful SNI extraction and validation
	SNIValidTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "egress_proxy_sni_valid_total",
			Help: "Total number of valid SNI hostnames (extracted and validated)",
		},
		[]string{"identity", "destination"},
	)

	// SNIValidationFailuresTotal counts SNI validation failures (connection closed)
	SNIValidationFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "egress_proxy_sni_validation_failures_total",
			Help: "Total number of SNI validation failures (potential DNS rebinding or not allowed)",
		},
		[]string{"identity", "destination"},
	)

	// SNINotExtractedTotal counts SNI extraction timeouts (non-TLS traffic)
	SNINotExtractedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "egress_proxy_sni_not_extracted_total",
			Help: "Total number of connections where SNI could not be extracted (likely non-TLS traffic)",
		},
	)

	// BytesTransferred counts bytes transferred between client and destination
	BytesTransferred = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "egress_proxy_bytes_transferred",
			Help: "Total number of bytes transferred between client and destination",
		},
		[]string{"identity", "destination", "direction"},
	)
)

// RecordRequest records a proxy request with status
// identityKey should be the matched config key, not the received identity
func RecordRequest(identityKey, destination, status string) {
	RequestsTotal.WithLabelValues(identityKey, destination, status).Inc()
}

// // RecordRequestDuration records request duration
// // identityKey should be the matched config key, not the received identity
// func RecordRequestDuration(identityKey, destination string, durationSec float64) {
// 	RequestDuration.WithLabelValues(identityKey, destination).Observe(durationSec)
// }

// RecordConfigReload increments the config reload counter
func RecordConfigReload() {
	ConfigReloadsTotal.Inc()
}

// RecordConfigLoadError increments the config load error counter
func RecordConfigLoadError() {
	ConfigLoadErrorsTotal.Inc()
}

// UpdateAllowedDestinations updates the allowed destinations gauge
// identity should be the config key (identity rule from the configuration), not a received identity
func UpdateAllowedDestinations(identity string, count int) {
	AllowedDestinations.WithLabelValues(identity).Set(float64(count))
}

// ClearAllowedDestinations clears all allowed destinations gauges
func ClearAllowedDestinations() {
	AllowedDestinations.Reset()
}

// RecordSNIValid records a successful SNI validation
// identityKey should be the matched config key, not the received identity
func RecordSNIValid(identityKey, destination string) {
	SNIValidTotal.WithLabelValues(identityKey, destination).Inc()
}

// RecordSNIValidationFailure records an SNI validation failure (connection closed)
// identityKey should be the matched config key, not the received identity
func RecordSNIValidationFailure(identityKey, destination string) {
	SNIValidationFailuresTotal.WithLabelValues(identityKey, destination).Inc()
}

// RecordSNINotExtracted records when SNI could not be extracted within timeout
func RecordSNINotExtracted() {
	SNINotExtractedTotal.Inc()
}

// RecordBytesTransferred records bytes transferred in a given direction
// identityKey should be the matched config key, not the received identity
// direction should be "egress" (client->destination) or "ingress" (destination->client)
func RecordBytesTransferred(identityKey, destination, direction string, bytes int64) {
	BytesTransferred.WithLabelValues(identityKey, destination, direction).Add(float64(bytes))
}
