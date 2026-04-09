package prometheus_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	obsprom "github.com/fosrl/gerbil/internal/observability/prometheus"
)

func newTestBackend(t *testing.T) *obsprom.Backend {
	t.Helper()
	b, err := obsprom.New(obsprom.Config{Path: "/metrics"})
	if err != nil {
		t.Fatalf("failed to create prometheus backend: %v", err)
	}
	return b
}

func TestPrometheusBackendHTTPHandler(t *testing.T) {
	b := newTestBackend(t)
	if b.HTTPHandler() == nil {
		t.Error("HTTPHandler should not be nil")
	}
}

func TestPrometheusBackendShutdown(t *testing.T) {
	b := newTestBackend(t)
	if err := b.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}

func TestPrometheusBackendCounter(t *testing.T) {
	b := newTestBackend(t)
	c := b.NewCounter("test_counter_total", "A test counter", "result")
	c.Add(context.Background(), 3, map[string]string{"result": "ok"})

	body := scrapeMetrics(t, b)
	assertMetricPresent(t, body, `test_counter_total{result="ok"} 3`)
}

func TestPrometheusBackendUpDownCounter(t *testing.T) {
	b := newTestBackend(t)
	u := b.NewUpDownCounter("test_gauge_total", "A test up-down counter", "state")
	u.Add(context.Background(), 5, map[string]string{"state": "active"})
	u.Add(context.Background(), -2, map[string]string{"state": "active"})

	body := scrapeMetrics(t, b)
	assertMetricPresent(t, body, `test_gauge_total{state="active"} 3`)
}

func TestPrometheusBackendInt64Gauge(t *testing.T) {
	b := newTestBackend(t)
	g := b.NewInt64Gauge("test_int_gauge", "An integer gauge", "ifname")
	g.Record(context.Background(), 42, map[string]string{"ifname": "wg0"})

	body := scrapeMetrics(t, b)
	assertMetricPresent(t, body, `test_int_gauge{ifname="wg0"} 42`)
}

func TestPrometheusBackendFloat64Gauge(t *testing.T) {
	b := newTestBackend(t)
	g := b.NewFloat64Gauge("test_float_gauge", "A float gauge", "cert")
	g.Record(context.Background(), 7.5, map[string]string{"cert": "example.com"})

	body := scrapeMetrics(t, b)
	assertMetricPresent(t, body, `test_float_gauge{cert="example.com"} 7.5`)
}

func TestPrometheusBackendHistogram(t *testing.T) {
	b := newTestBackend(t)
	buckets := []float64{0.1, 0.5, 1.0, 5.0}
	h := b.NewHistogram("test_duration_seconds", "A test histogram", buckets, "method")
	h.Record(context.Background(), 0.3, map[string]string{"method": "GET"})

	body := scrapeMetrics(t, b)
	if !strings.Contains(body, "test_duration_seconds") {
		t.Errorf("expected histogram metric in output, body:\n%s", body)
	}
}

func TestPrometheusBackendMultipleLabels(t *testing.T) {
	b := newTestBackend(t)
	c := b.NewCounter("multi_label_total", "Multi-label counter", "method", "route", "status_code")
	c.Add(context.Background(), 1, map[string]string{
		"method":      "POST",
		"route":       "/api/peers",
		"status_code": "200",
	})

	body := scrapeMetrics(t, b)
	if !strings.Contains(body, "multi_label_total") {
		t.Errorf("expected multi_label_total in output, body:\n%s", body)
	}
}

func TestPrometheusBackendGoMetrics(t *testing.T) {
	b := newTestBackend(t)
	body := scrapeMetrics(t, b)
	// Default backend includes Go runtime metrics.
	if !strings.Contains(body, "go_goroutines") {
		t.Error("expected go_goroutines in default backend output")
	}
}

func TestPrometheusBackendNoGoMetrics(t *testing.T) {
	f := false
	b, err := obsprom.New(obsprom.Config{IncludeGoMetrics: &f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := scrapeMetrics(t, b)
	if strings.Contains(body, "go_goroutines") {
		t.Error("expected no go_goroutines when IncludeGoMetrics=false")
	}
}

func TestPrometheusBackendNilLabels(t *testing.T) {
	// Adding with nil labels should not panic (treated as empty map).
	b := newTestBackend(t)
	c := b.NewCounter("nil_labels_total", "counter with no labels")
	// nil labels with no label names declared should be safe
	c.Add(context.Background(), 1, nil)
}

func TestPrometheusBackendConcurrentAdd(t *testing.T) {
	b := newTestBackend(t)
	c := b.NewCounter("concurrent_total", "concurrent counter", "worker")

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(_ int) {
			for j := 0; j < 100; j++ {
				c.Add(context.Background(), 1, map[string]string{"worker": "w"})
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	body := scrapeMetrics(t, b)
	assertMetricPresent(t, body, `concurrent_total{worker="w"} 1000`)
}

// --- helpers ---

func scrapeMetrics(t *testing.T, b *obsprom.Backend) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	rr := httptest.NewRecorder()
	b.HTTPHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics handler returned %d", rr.Code)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return string(body)
}

func assertMetricPresent(t *testing.T, body, expected string) {
	t.Helper()
	if !strings.Contains(body, expected) {
		t.Errorf("expected %q in metrics output\nbody:\n%s", expected, body)
	}
}
