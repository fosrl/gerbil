package observability_test

import (
	"context"
	"testing"

	"github.com/fosrl/gerbil/internal/observability"
)

func TestNoopBackendAllInstruments(t *testing.T) {
	n := &observability.NoopBackend{}

	ctx := context.Background()
	labels := observability.Labels{"k": "v"}

	t.Run("Counter", func(_ *testing.T) {
		c := n.NewCounter("test_counter", "desc")
		c.Add(ctx, 1, labels)
		c.Add(ctx, 0, nil)
	})

	t.Run("UpDownCounter", func(_ *testing.T) {
		u := n.NewUpDownCounter("test_updown", "desc")
		u.Add(ctx, 1, labels)
		u.Add(ctx, -1, nil)
	})

	t.Run("Int64Gauge", func(_ *testing.T) {
		g := n.NewInt64Gauge("test_int64gauge", "desc")
		g.Record(ctx, 42, labels)
		g.Record(ctx, 0, nil)
	})

	t.Run("Float64Gauge", func(_ *testing.T) {
		g := n.NewFloat64Gauge("test_float64gauge", "desc")
		g.Record(ctx, 3.14, labels)
		g.Record(ctx, 0, nil)
	})

	t.Run("Histogram", func(_ *testing.T) {
		h := n.NewHistogram("test_histogram", "desc", []float64{1, 5, 10})
		h.Record(ctx, 2.5, labels)
		h.Record(ctx, 0, nil)
	})

	t.Run("HTTPHandler", func(t *testing.T) {
		if n.HTTPHandler() != nil {
			t.Error("noop HTTPHandler should be nil")
		}
	})

	t.Run("Shutdown", func(t *testing.T) {
		if err := n.Shutdown(ctx); err != nil {
			t.Errorf("noop Shutdown should not error: %v", err)
		}
	})
}

func TestNoopBackendLabelNames(_ *testing.T) {
	// Verify that label names passed at creation time are accepted without panic.
	n := &observability.NoopBackend{}
	n.NewCounter("c", "d", "label1", "label2")
	n.NewUpDownCounter("u", "d", "l1")
	n.NewInt64Gauge("g1", "d", "l1", "l2", "l3")
	n.NewFloat64Gauge("g2", "d")
	n.NewHistogram("h", "d", []float64{0.1, 1.0}, "l1")
}
