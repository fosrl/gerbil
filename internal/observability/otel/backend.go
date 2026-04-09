// Package otel implements the OpenTelemetry metrics backend for Gerbil.
//
// Metrics are exported via OTLP (gRPC or HTTP) to an external collector.
// No Prometheus /metrics endpoint is exposed in this mode.
// Future OTel tracing and logging can be added alongside this package
// without touching the Prometheus-native path.
package otel

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Config holds OTel backend configuration.
type Config struct {
	// Protocol is "grpc" (default) or "http".
	Protocol string

	// Endpoint is the OTLP collector address.
	Endpoint string

	// Insecure disables TLS.
	Insecure bool

	// ExportInterval is the period between pushes to the collector.
	ExportInterval time.Duration

	ServiceName           string
	ServiceVersion        string
	DeploymentEnvironment string
}

// Backend is the OTel metrics backend.
type Backend struct {
	cfg      Config
	provider *sdkmetric.MeterProvider
	meter    metric.Meter
}

// New creates and initialises an OTel backend.
//
// cfg.Protocol must be "grpc" (default) or "http".
// cfg.Endpoint is the OTLP collector address (e.g. "localhost:4317").
// cfg.ExportInterval sets the push period (defaults to 60 s if ≤ 0).
// cfg.Insecure disables TLS on the OTLP connection.
//
// Connection to the collector is established lazily; New only validates cfg
// and creates the SDK components. It returns an error only if the OTel resource
// or exporter cannot be constructed.
func New(cfg Config) (*Backend, error) {
	if cfg.Protocol == "" {
		cfg.Protocol = "grpc"
	}
	if cfg.ExportInterval <= 0 {
		cfg.ExportInterval = 60 * time.Second
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "gerbil"
	}

	res, err := newResource(cfg.ServiceName, cfg.ServiceVersion, cfg.DeploymentEnvironment)
	if err != nil {
		return nil, fmt.Errorf("otel backend: build resource: %w", err)
	}

	exp, err := newExporter(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("otel backend: create exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exp,
		sdkmetric.WithInterval(cfg.ExportInterval),
	)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)

	meter := provider.Meter("github.com/fosrl/gerbil")

	return &Backend{cfg: cfg, provider: provider, meter: meter}, nil
}

// HTTPHandler returns nil – the OTel backend does not expose an HTTP endpoint.
func (b *Backend) HTTPHandler() http.Handler {
	_ = b
	return nil
}

// Shutdown flushes pending metrics and shuts down the MeterProvider.
func (b *Backend) Shutdown(ctx context.Context) error {
	return b.provider.Shutdown(ctx)
}

// NewCounter creates an OTel Int64Counter.
func (b *Backend) NewCounter(name, desc string, _ ...string) *Counter {
	c, err := b.meter.Int64Counter(name, metric.WithDescription(desc))
	if err != nil {
		panic(fmt.Sprintf("otel: create counter %q: %v", name, err))
	}
	return &Counter{c: c}
}

// NewUpDownCounter creates an OTel Int64UpDownCounter.
func (b *Backend) NewUpDownCounter(name, desc string, _ ...string) *UpDownCounter {
	c, err := b.meter.Int64UpDownCounter(name, metric.WithDescription(desc))
	if err != nil {
		panic(fmt.Sprintf("otel: create up-down counter %q: %v", name, err))
	}
	return &UpDownCounter{c: c}
}

// NewInt64Gauge creates an OTel Int64Gauge.
func (b *Backend) NewInt64Gauge(name, desc string, _ ...string) *Int64Gauge {
	g, err := b.meter.Int64Gauge(name, metric.WithDescription(desc))
	if err != nil {
		panic(fmt.Sprintf("otel: create int64 gauge %q: %v", name, err))
	}
	return &Int64Gauge{g: g}
}

// NewFloat64Gauge creates an OTel Float64Gauge.
func (b *Backend) NewFloat64Gauge(name, desc string, _ ...string) *Float64Gauge {
	g, err := b.meter.Float64Gauge(name, metric.WithDescription(desc))
	if err != nil {
		panic(fmt.Sprintf("otel: create float64 gauge %q: %v", name, err))
	}
	return &Float64Gauge{g: g}
}

// NewHistogram creates an OTel Float64Histogram with explicit bucket boundaries.
func (b *Backend) NewHistogram(name, desc string, buckets []float64, _ ...string) *Histogram {
	h, err := b.meter.Float64Histogram(name,
		metric.WithDescription(desc),
		metric.WithExplicitBucketBoundaries(buckets...),
	)
	if err != nil {
		panic(fmt.Sprintf("otel: create histogram %q: %v", name, err))
	}
	return &Histogram{h: h}
}

// labelsToAttrs converts a Labels map to OTel attribute key-value pairs.
func labelsToAttrs(labels map[string]string) []attribute.KeyValue {
	if len(labels) == 0 {
		return nil
	}
	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}

// Counter wraps an OTel Int64Counter.
type Counter struct {
	c metric.Int64Counter
}

// Add increments the counter by value.
func (c *Counter) Add(ctx context.Context, value int64, labels map[string]string) {
	c.c.Add(ctx, value, metric.WithAttributes(labelsToAttrs(labels)...))
}

// UpDownCounter wraps an OTel Int64UpDownCounter.
type UpDownCounter struct {
	c metric.Int64UpDownCounter
}

// Add adjusts the up-down counter by value.
func (u *UpDownCounter) Add(ctx context.Context, value int64, labels map[string]string) {
	u.c.Add(ctx, value, metric.WithAttributes(labelsToAttrs(labels)...))
}

// Int64Gauge wraps an OTel Int64Gauge.
type Int64Gauge struct {
	g metric.Int64Gauge
}

// Record sets the gauge to value.
func (g *Int64Gauge) Record(ctx context.Context, value int64, labels map[string]string) {
	g.g.Record(ctx, value, metric.WithAttributes(labelsToAttrs(labels)...))
}

// Float64Gauge wraps an OTel Float64Gauge.
type Float64Gauge struct {
	g metric.Float64Gauge
}

// Record sets the gauge to value.
func (g *Float64Gauge) Record(ctx context.Context, value float64, labels map[string]string) {
	g.g.Record(ctx, value, metric.WithAttributes(labelsToAttrs(labels)...))
}

// Histogram wraps an OTel Float64Histogram.
type Histogram struct {
	h metric.Float64Histogram
}

// Record observes value in the histogram.
func (h *Histogram) Record(ctx context.Context, value float64, labels map[string]string) {
	h.h.Record(ctx, value, metric.WithAttributes(labelsToAttrs(labels)...))
}
