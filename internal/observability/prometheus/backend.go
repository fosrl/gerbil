// Package prometheus implements the native Prometheus metrics backend for Gerbil.
//
// This backend uses the Prometheus Go client directly; it does NOT depend on the
// OpenTelemetry SDK.  A dedicated Prometheus registry is used so that default
// Go/process metrics are not unintentionally included unless the caller opts in.
package prometheus

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds Prometheus-backend configuration.
type Config struct {
	// Path is the HTTP endpoint path (e.g. "/metrics").
	Path string

	// IncludeGoMetrics controls whether the standard Go runtime and process
	// collectors are registered on the dedicated registry.
	// Defaults to true if not explicitly set.
	IncludeGoMetrics *bool
}

// Backend is the native Prometheus metrics backend.
// Metric instruments are created via the New* family of methods and stored
// in the backend-specific instrument types that implement the observability
// instrument interfaces.
type Backend struct {
	cfg      Config
	registry *prometheus.Registry
	handler  http.Handler
}

// New creates and initialises a Prometheus backend.
//
// cfg.Path sets the HTTP endpoint path (defaults to "/metrics" if empty).
// cfg.IncludeGoMetrics controls whether standard Go runtime and process metrics
// are included; defaults to true when nil.
//
// Returns an error if the registry cannot be created.
func New(cfg Config) (*Backend, error) {
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}

	registry := prometheus.NewRegistry()

	// Include Go and process metrics by default.
	includeGo := cfg.IncludeGoMetrics == nil || *cfg.IncludeGoMetrics
	if includeGo {
		registry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}

	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: false,
	})

	return &Backend{cfg: cfg, registry: registry, handler: handler}, nil
}

// HTTPHandler returns the Prometheus /metrics HTTP handler.
func (b *Backend) HTTPHandler() http.Handler {
	return b.handler
}

// Shutdown is a no-op for the Prometheus backend.
// The registry does not maintain background goroutines.
func (b *Backend) Shutdown(_ context.Context) error {
	_ = b
	return nil
}

// NewCounter creates a Prometheus CounterVec registered on the backend's registry.
func (b *Backend) NewCounter(name, desc string, labelNames ...string) *Counter {
	vec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: desc,
	}, labelNames)
	b.registry.MustRegister(vec)
	return &Counter{vec: vec}
}

// NewUpDownCounter creates a Prometheus GaugeVec (Prometheus gauges are
// bidirectional) registered on the backend's registry.
func (b *Backend) NewUpDownCounter(name, desc string, labelNames ...string) *UpDownCounter {
	vec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: desc,
	}, labelNames)
	b.registry.MustRegister(vec)
	return &UpDownCounter{vec: vec}
}

// NewInt64Gauge creates a Prometheus GaugeVec registered on the backend's registry.
func (b *Backend) NewInt64Gauge(name, desc string, labelNames ...string) *Int64Gauge {
	vec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: desc,
	}, labelNames)
	b.registry.MustRegister(vec)
	return &Int64Gauge{vec: vec}
}

// NewFloat64Gauge creates a Prometheus GaugeVec registered on the backend's registry.
func (b *Backend) NewFloat64Gauge(name, desc string, labelNames ...string) *Float64Gauge {
	vec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: desc,
	}, labelNames)
	b.registry.MustRegister(vec)
	return &Float64Gauge{vec: vec}
}

// NewHistogram creates a Prometheus HistogramVec registered on the backend's registry.
func (b *Backend) NewHistogram(name, desc string, buckets []float64, labelNames ...string) *Histogram {
	vec := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    desc,
		Buckets: buckets,
	}, labelNames)
	b.registry.MustRegister(vec)
	return &Histogram{vec: vec}
}

// Counter is a native Prometheus counter instrument.
type Counter struct {
	vec *prometheus.CounterVec
}

// Add increments the counter by value for the given labels.
//
// value must be non-negative. Negative values are ignored.
func (c *Counter) Add(_ context.Context, value int64, labels map[string]string) {
	if value < 0 {
		return
	}
	c.vec.With(prometheus.Labels(labels)).Add(float64(value))
}

// UpDownCounter is a native Prometheus gauge used as a bidirectional counter.
type UpDownCounter struct {
	vec *prometheus.GaugeVec
}

// Add adjusts the gauge by value for the given labels.
func (u *UpDownCounter) Add(_ context.Context, value int64, labels map[string]string) {
	u.vec.With(prometheus.Labels(labels)).Add(float64(value))
}

// Int64Gauge is a native Prometheus gauge recording integer snapshot values.
type Int64Gauge struct {
	vec *prometheus.GaugeVec
}

// Record sets the gauge to value for the given labels.
func (g *Int64Gauge) Record(_ context.Context, value int64, labels map[string]string) {
	g.vec.With(prometheus.Labels(labels)).Set(float64(value))
}

// Float64Gauge is a native Prometheus gauge recording float snapshot values.
type Float64Gauge struct {
	vec *prometheus.GaugeVec
}

// Record sets the gauge to value for the given labels.
func (g *Float64Gauge) Record(_ context.Context, value float64, labels map[string]string) {
	g.vec.With(prometheus.Labels(labels)).Set(value)
}

// Histogram is a native Prometheus histogram instrument.
type Histogram struct {
	vec *prometheus.HistogramVec
}

// Record observes value for the given labels.
func (h *Histogram) Record(_ context.Context, value float64, labels map[string]string) {
	h.vec.With(prometheus.Labels(labels)).Observe(value)
}
