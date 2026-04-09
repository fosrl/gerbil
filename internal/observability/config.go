// Package observability provides a backend-neutral metrics abstraction for Gerbil.
//
// Exactly one metrics backend may be enabled at runtime:
//   - "prometheus" – native Prometheus client; exposes /metrics (no OTel SDK required)
//   - "otel"       – OpenTelemetry metrics pushed via OTLP (gRPC or HTTP)
//   - "none"       – metrics disabled; a safe noop implementation is used
//
// Future OTel tracing and logging can be added to this package alongside the
// existing otel sub-package without touching the Prometheus-native path.
package observability

import (
	"fmt"
	"time"
)

// MetricsConfig is the top-level metrics configuration.
type MetricsConfig struct {
	// Enabled controls whether any metrics backend is started.
	// When false the noop backend is used regardless of Backend.
	Enabled bool

	// Backend selects the active backend: "prometheus", "otel", or "none".
	Backend string

	// Prometheus holds settings used only by the Prometheus-native backend.
	Prometheus PrometheusConfig

	// OTel holds settings used only by the OTel backend.
	OTel OTelConfig

	// ServiceName is propagated to OTel resource attributes.
	ServiceName string

	// ServiceVersion is propagated to OTel resource attributes.
	ServiceVersion string

	// DeploymentEnvironment is an optional OTel resource attribute.
	DeploymentEnvironment string
}

// PrometheusConfig holds Prometheus-native backend settings.
type PrometheusConfig struct {
	// Path is the HTTP path to expose the /metrics endpoint.
	// Defaults to "/metrics".
	Path string
}

// OTelConfig holds OpenTelemetry backend settings.
type OTelConfig struct {
	// Protocol is the OTLP transport: "grpc" (default) or "http".
	Protocol string

	// Endpoint is the OTLP collector address (e.g. "localhost:4317").
	Endpoint string

	// Insecure disables TLS for the OTLP connection.
	Insecure bool

	// ExportInterval is how often metrics are pushed to the collector.
	// Defaults to 60 s.
	ExportInterval time.Duration
}

// DefaultMetricsConfig returns a MetricsConfig with sensible defaults.
func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled: true,
		Backend: "prometheus",
		Prometheus: PrometheusConfig{
			Path: "/metrics",
		},
		OTel: OTelConfig{
			Protocol:       "grpc",
			Endpoint:       "localhost:4317",
			Insecure:       true,
			ExportInterval: 60 * time.Second,
		},
		ServiceName:    "gerbil",
		ServiceVersion: "1.0.0",
	}
}

// Validate checks the configuration for logical errors.
func (c *MetricsConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	switch c.Backend {
	case "prometheus", "none", "":
		// valid
	case "otel":
		if c.OTel.Endpoint == "" {
			return fmt.Errorf("metrics: backend=otel requires a non-empty OTel endpoint")
		}
		if c.OTel.Protocol != "grpc" && c.OTel.Protocol != "http" {
			return fmt.Errorf("metrics: otel protocol must be \"grpc\" or \"http\", got %q", c.OTel.Protocol)
		}
		if c.OTel.ExportInterval <= 0 {
			return fmt.Errorf("metrics: otel export interval must be positive")
		}
	default:
		return fmt.Errorf("metrics: unknown backend %q (must be \"prometheus\", \"otel\", or \"none\")", c.Backend)
	}

	return nil
}

// effectiveBackend resolves the backend string, treating "" and "none" as noop.
func (c *MetricsConfig) effectiveBackend() string {
	if !c.Enabled {
		return "none"
	}
	if c.Backend == "" {
		return "none"
	}
	return c.Backend
}
