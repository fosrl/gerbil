package observability

import (
	"context"
	"fmt"
	"net/http"

	obsotel "github.com/fosrl/gerbil/internal/observability/otel"
	obsprom "github.com/fosrl/gerbil/internal/observability/prometheus"
)

// Labels is a set of key-value pairs attached to a metric observation.
// Use only stable, bounded-cardinality label values.
type Labels = map[string]string

// Counter is a monotonically increasing instrument.
type Counter interface {
	Add(ctx context.Context, value int64, labels Labels)
}

// UpDownCounter is a bidirectional integer instrument (can go up or down).
type UpDownCounter interface {
	Add(ctx context.Context, value int64, labels Labels)
}

// Int64Gauge records a snapshot integer value.
type Int64Gauge interface {
	Record(ctx context.Context, value int64, labels Labels)
}

// Float64Gauge records a snapshot float value.
type Float64Gauge interface {
	Record(ctx context.Context, value float64, labels Labels)
}

// Histogram records a distribution of values.
type Histogram interface {
	Record(ctx context.Context, value float64, labels Labels)
}

// Backend is the single interface that each metrics implementation must satisfy.
// Application code must not import backend-specific packages (prometheus, otel).
type Backend interface {
	// NewCounter creates a counter metric.
	// labelNames declares the set of label keys that will be passed at observation time.
	NewCounter(name, desc string, labelNames ...string) Counter

	// NewUpDownCounter creates an up-down counter metric.
	NewUpDownCounter(name, desc string, labelNames ...string) UpDownCounter

	// NewInt64Gauge creates an integer gauge metric.
	NewInt64Gauge(name, desc string, labelNames ...string) Int64Gauge

	// NewFloat64Gauge creates a float gauge metric.
	NewFloat64Gauge(name, desc string, labelNames ...string) Float64Gauge

	// NewHistogram creates a histogram metric.
	// buckets are the explicit upper-bound bucket boundaries.
	NewHistogram(name, desc string, buckets []float64, labelNames ...string) Histogram

	// HTTPHandler returns the /metrics HTTP handler.
	// Implementations that do not expose an HTTP endpoint return nil.
	HTTPHandler() http.Handler

	// Shutdown performs a graceful flush / shutdown of the backend.
	Shutdown(ctx context.Context) error
}

// New creates the backend selected by cfg and returns it.
// Exactly one backend is created; the selection is mutually exclusive.
func New(cfg MetricsConfig) (Backend, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	switch cfg.effectiveBackend() {
	case "prometheus":
		b, err := obsprom.New(obsprom.Config{
			Path: cfg.Prometheus.Path,
		})
		if err != nil {
			return nil, err
		}
		return &promAdapter{b: b}, nil
	case "otel":
		b, err := obsotel.New(obsotel.Config{
			Protocol:              cfg.OTel.Protocol,
			Endpoint:              cfg.OTel.Endpoint,
			Insecure:              cfg.OTel.Insecure,
			ExportInterval:        cfg.OTel.ExportInterval,
			ServiceName:           cfg.ServiceName,
			ServiceVersion:        cfg.ServiceVersion,
			DeploymentEnvironment: cfg.DeploymentEnvironment,
		})
		if err != nil {
			return nil, err
		}
		return &otelAdapter{b: b}, nil
	case "none":
		return &NoopBackend{}, nil
	default:
		return nil, fmt.Errorf("observability: unknown backend %q", cfg.effectiveBackend())
	}
}

// promAdapter wraps obsprom.Backend to implement the observability.Backend interface.
// The concrete instrument types from the prometheus sub-package satisfy the instrument
// interfaces via Go's structural (duck) typing without importing this package.
type promAdapter struct {
	b *obsprom.Backend
}

func (a *promAdapter) NewCounter(name, desc string, labelNames ...string) Counter {
	return a.b.NewCounter(name, desc, labelNames...)
}
func (a *promAdapter) NewUpDownCounter(name, desc string, labelNames ...string) UpDownCounter {
	return a.b.NewUpDownCounter(name, desc, labelNames...)
}
func (a *promAdapter) NewInt64Gauge(name, desc string, labelNames ...string) Int64Gauge {
	return a.b.NewInt64Gauge(name, desc, labelNames...)
}
func (a *promAdapter) NewFloat64Gauge(name, desc string, labelNames ...string) Float64Gauge {
	return a.b.NewFloat64Gauge(name, desc, labelNames...)
}
func (a *promAdapter) NewHistogram(name, desc string, buckets []float64, labelNames ...string) Histogram {
	return a.b.NewHistogram(name, desc, buckets, labelNames...)
}
func (a *promAdapter) HTTPHandler() http.Handler          { return a.b.HTTPHandler() }
func (a *promAdapter) Shutdown(ctx context.Context) error { return a.b.Shutdown(ctx) }

// otelAdapter wraps obsotel.Backend to implement the observability.Backend interface.
type otelAdapter struct {
	b *obsotel.Backend
}

func (a *otelAdapter) NewCounter(name, desc string, labelNames ...string) Counter {
	return a.b.NewCounter(name, desc, labelNames...)
}
func (a *otelAdapter) NewUpDownCounter(name, desc string, labelNames ...string) UpDownCounter {
	return a.b.NewUpDownCounter(name, desc, labelNames...)
}
func (a *otelAdapter) NewInt64Gauge(name, desc string, labelNames ...string) Int64Gauge {
	return a.b.NewInt64Gauge(name, desc, labelNames...)
}
func (a *otelAdapter) NewFloat64Gauge(name, desc string, labelNames ...string) Float64Gauge {
	return a.b.NewFloat64Gauge(name, desc, labelNames...)
}
func (a *otelAdapter) NewHistogram(name, desc string, buckets []float64, labelNames ...string) Histogram {
	return a.b.NewHistogram(name, desc, buckets, labelNames...)
}
func (a *otelAdapter) HTTPHandler() http.Handler          { return a.b.HTTPHandler() }
func (a *otelAdapter) Shutdown(ctx context.Context) error { return a.b.Shutdown(ctx) }
