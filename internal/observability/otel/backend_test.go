package otel_test

import (
	"context"
	"testing"
	"time"

	obsotel "github.com/fosrl/gerbil/internal/observability/otel"
)

const (
	defaultGRPCEndpoint = "localhost:4317"
	defaultServiceName  = "gerbil-test"
)

func newInMemoryBackend(t *testing.T) *obsotel.Backend {
	t.Helper()
	// Use a very short export interval; an in-process collector (noop exporter)
	// is used by pointing to a non-existent endpoint with insecure mode.
	// The backend itself should initialise without error since connection is lazy.
	b, err := obsotel.New(obsotel.Config{
		Protocol:       "grpc",
		Endpoint:       defaultGRPCEndpoint,
		Insecure:       true,
		ExportInterval: 100 * time.Millisecond,
		ServiceName:    defaultServiceName,
		ServiceVersion: "0.0.1",
	})
	if err != nil {
		t.Fatalf("failed to create otel backend: %v", err)
	}
	return b
}

func TestOtelBackendHTTPHandlerIsNil(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck
	if b.HTTPHandler() != nil {
		t.Error("OTel backend HTTPHandler should return nil")
	}
}

func TestOtelBackendShutdown(t *testing.T) {
	b := newInMemoryBackend(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx); err != nil {
		// Shutdown with unreachable collector may fail to flush; that's acceptable.
		// What matters is that Shutdown does not panic.
		t.Logf("Shutdown returned (expected with no collector): %v", err)
	}
}

func TestOtelBackendCounter(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck

	c := b.NewCounter("gerbil_test_counter_total", "test counter", "result")
	// Should not panic
	c.Add(context.Background(), 1, map[string]string{"result": "ok"})
	c.Add(context.Background(), 5, nil)
}

func TestOtelBackendUpDownCounter(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck

	u := b.NewUpDownCounter("gerbil_test_updown", "test updown", "state")
	u.Add(context.Background(), 3, map[string]string{"state": "active"})
	u.Add(context.Background(), -1, map[string]string{"state": "active"})
}

func TestOtelBackendInt64Gauge(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck

	g := b.NewInt64Gauge("gerbil_test_int_gauge", "test gauge")
	g.Record(context.Background(), 42, nil)
}

func TestOtelBackendFloat64Gauge(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck

	g := b.NewFloat64Gauge("gerbil_test_float_gauge", "test float gauge")
	g.Record(context.Background(), 3.14, nil)
}

func TestOtelBackendHistogram(t *testing.T) {
	b := newInMemoryBackend(t)
	defer b.Shutdown(context.Background()) //nolint:errcheck

	h := b.NewHistogram("gerbil_test_duration_seconds", "test histogram",
		[]float64{0.1, 0.5, 1.0}, "method")
	h.Record(context.Background(), 0.3, map[string]string{"method": "GET"})
}

func TestOtelBackendHTTPProtocol(t *testing.T) {
	b, err := obsotel.New(obsotel.Config{
		Protocol:       "http",
		Endpoint:       "localhost:4318",
		Insecure:       true,
		ExportInterval: 100 * time.Millisecond,
		ServiceName:    defaultServiceName,
	})
	if err != nil {
		t.Fatalf("failed to create otel http backend: %v", err)
	}
	defer b.Shutdown(context.Background()) //nolint:errcheck

	if b.HTTPHandler() != nil {
		t.Error("OTel HTTP backend should not expose a /metrics endpoint")
	}
}

func TestOtelBackendInvalidProtocol(t *testing.T) {
	_, err := obsotel.New(obsotel.Config{
		Protocol:       "tcp",
		Endpoint:       defaultGRPCEndpoint,
		ExportInterval: 10 * time.Second,
	})
	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestOtelBackendDeploymentEnvironment(t *testing.T) {
	b, err := obsotel.New(obsotel.Config{
		Protocol:              "grpc",
		Endpoint:              defaultGRPCEndpoint,
		Insecure:              true,
		ExportInterval:        100 * time.Millisecond,
		ServiceName:           defaultServiceName,
		ServiceVersion:        "1.2.3",
		DeploymentEnvironment: "staging",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer b.Shutdown(context.Background()) //nolint:errcheck
}
