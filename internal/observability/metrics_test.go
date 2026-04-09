package observability_test

import (
	"context"
	"testing"
	"time"

	"github.com/fosrl/gerbil/internal/observability"
)

const (
	defaultMetricsPath = "/metrics"
	otelGRPCEndpoint   = "localhost:4317"
	errUnexpectedFmt   = "unexpected error: %v"
)

func TestDefaultMetricsConfig(t *testing.T) {
	cfg := observability.DefaultMetricsConfig()
	if !cfg.Enabled {
		t.Error("default config should have Enabled=true")
	}
	if cfg.Backend != "prometheus" {
		t.Errorf("default backend should be prometheus, got %q", cfg.Backend)
	}
	if cfg.Prometheus.Path != defaultMetricsPath {
		t.Errorf("default prometheus path should be %s, got %q", defaultMetricsPath, cfg.Prometheus.Path)
	}
	if cfg.OTel.Protocol != "grpc" {
		t.Errorf("default otel protocol should be grpc, got %q", cfg.OTel.Protocol)
	}
	if cfg.OTel.ExportInterval != 60*time.Second {
		t.Errorf("default otel export interval should be 60s, got %v", cfg.OTel.ExportInterval)
	}
}
func TestValidateValidConfigs(t *testing.T) {
	tests := []struct {
		name string
		cfg  observability.MetricsConfig
	}{
		{name: "disabled", cfg: observability.MetricsConfig{Enabled: false}},
		{name: "backend none", cfg: observability.MetricsConfig{Enabled: true, Backend: "none"}},
		{name: "backend empty", cfg: observability.MetricsConfig{Enabled: true, Backend: ""}},
		{name: "prometheus", cfg: observability.MetricsConfig{Enabled: true, Backend: "prometheus"}},
		{
			name: "otel grpc",
			cfg: observability.MetricsConfig{
				Enabled: true, Backend: "otel",
				OTel: observability.OTelConfig{Protocol: "grpc", Endpoint: otelGRPCEndpoint, ExportInterval: 10 * time.Second},
			},
		},
		{
			name: "otel http",
			cfg: observability.MetricsConfig{
				Enabled: true, Backend: "otel",
				OTel: observability.OTelConfig{Protocol: "http", Endpoint: "localhost:4318", ExportInterval: 30 * time.Second},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateInvalidConfigs(t *testing.T) {
	tests := []struct {
		name string
		cfg  observability.MetricsConfig
	}{
		{name: "unknown backend", cfg: observability.MetricsConfig{Enabled: true, Backend: "datadog"}},
		{
			name: "otel missing endpoint",
			cfg: observability.MetricsConfig{
				Enabled: true, Backend: "otel",
				OTel: observability.OTelConfig{Protocol: "grpc", Endpoint: "", ExportInterval: 10 * time.Second},
			},
		},
		{
			name: "otel invalid protocol",
			cfg: observability.MetricsConfig{
				Enabled: true, Backend: "otel",
				OTel: observability.OTelConfig{Protocol: "tcp", Endpoint: otelGRPCEndpoint, ExportInterval: 10 * time.Second},
			},
		},
		{
			name: "otel zero interval",
			cfg: observability.MetricsConfig{
				Enabled: true, Backend: "otel",
				OTel: observability.OTelConfig{Protocol: "grpc", Endpoint: otelGRPCEndpoint, ExportInterval: 0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Error("expected validation error but got nil")
			}
		})
	}
}

func TestNewNoopBackend(t *testing.T) {
	b, err := observability.New(observability.MetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf(errUnexpectedFmt, err)
	}
	if b.HTTPHandler() != nil {
		t.Error("noop backend HTTPHandler should return nil")
	}
}

func TestNewNoneBackend(t *testing.T) {
	b, err := observability.New(observability.MetricsConfig{Enabled: true, Backend: "none"})
	if err != nil {
		t.Fatalf(errUnexpectedFmt, err)
	}
	if b.HTTPHandler() != nil {
		t.Error("none backend HTTPHandler should return nil")
	}
}

func TestNewPrometheusBackend(t *testing.T) {
	cfg := observability.MetricsConfig{
		Enabled: true, Backend: "prometheus",
		Prometheus: observability.PrometheusConfig{Path: defaultMetricsPath},
	}
	b, err := observability.New(cfg)
	if err != nil {
		t.Fatalf(errUnexpectedFmt, err)
	}
	if b.HTTPHandler() == nil {
		t.Error("prometheus backend HTTPHandler should not be nil")
	}
	if err := b.Shutdown(context.Background()); err != nil {
		t.Errorf("prometheus shutdown error: %v", err)
	}
}

func TestNewInvalidBackend(t *testing.T) {
	_, err := observability.New(observability.MetricsConfig{Enabled: true, Backend: "invalid"})
	if err == nil {
		t.Error("expected error for invalid backend")
	}
}

func TestPrometheusAdapterAllInstruments(t *testing.T) {
	b, err := observability.New(observability.MetricsConfig{
		Enabled: true, Backend: "prometheus",
		Prometheus: observability.PrometheusConfig{Path: defaultMetricsPath},
	})
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}
	ctx := context.Background()
	labels := observability.Labels{"k": "v"}

	b.NewCounter("prom_adapter_counter_total", "desc", "k").Add(ctx, 1, labels)
	b.NewUpDownCounter("prom_adapter_updown", "desc", "k").Add(ctx, 2, labels)
	b.NewInt64Gauge("prom_adapter_int_gauge", "desc", "k").Record(ctx, 99, labels)
	b.NewFloat64Gauge("prom_adapter_float_gauge", "desc", "k").Record(ctx, 1.23, labels)
	b.NewHistogram("prom_adapter_histogram", "desc", []float64{0.1, 1.0}, "k").Record(ctx, 0.5, labels)

	if b.HTTPHandler() == nil {
		t.Error("prometheus adapter HTTPHandler should not be nil")
	}
	if err := b.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown error: %v", err)
	}
}

func TestOtelAdapterAllInstruments(t *testing.T) {
	b, err := observability.New(observability.MetricsConfig{
		Enabled: true, Backend: "otel",
		OTel: observability.OTelConfig{Protocol: "grpc", Endpoint: otelGRPCEndpoint, Insecure: true, ExportInterval: 100 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("failed to create otel backend: %v", err)
	}
	ctx := context.Background()
	labels := observability.Labels{"k": "v"}

	b.NewCounter("otel_adapter_counter_total", "desc", "k").Add(ctx, 1, labels)
	b.NewUpDownCounter("otel_adapter_updown", "desc", "k").Add(ctx, 2, labels)
	b.NewInt64Gauge("otel_adapter_int_gauge", "desc", "k").Record(ctx, 99, labels)
	b.NewFloat64Gauge("otel_adapter_float_gauge", "desc", "k").Record(ctx, 1.23, labels)
	b.NewHistogram("otel_adapter_histogram", "desc", []float64{0.1, 1.0}, "k").Record(ctx, 0.5, labels)

	if b.HTTPHandler() != nil {
		t.Error("OTel adapter HTTPHandler should be nil")
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b.Shutdown(shutdownCtx) //nolint:errcheck
}
