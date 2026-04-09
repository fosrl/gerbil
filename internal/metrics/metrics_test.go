package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fosrl/gerbil/internal/metrics"
	"github.com/fosrl/gerbil/internal/observability"
)

const exampleHostname = "example.com"

func initPrometheus(t *testing.T) http.Handler {
	t.Helper()
	cfg := metrics.DefaultConfig()
	cfg.Enabled = true
	cfg.Backend = "prometheus"
	cfg.Prometheus.Path = "/metrics"

	h, err := metrics.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	t.Cleanup(func() {
		metrics.Shutdown(context.Background()) //nolint:errcheck
	})
	return h
}

func initNoop(t *testing.T) {
	t.Helper()
	cfg := metrics.DefaultConfig()
	cfg.Enabled = false
	_, err := metrics.Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize noop failed: %v", err)
	}
	t.Cleanup(func() {
		metrics.Shutdown(context.Background()) //nolint:errcheck
	})
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("scrape returned %d", rr.Code)
	}
	b, _ := io.ReadAll(rr.Body)
	return string(b)
}

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("expected %q in output\nbody:\n%s", substr, body)
	}
}

// --- Tests ---

func TestInitializePrometheus(t *testing.T) {
	h := initPrometheus(t)
	if h == nil {
		t.Error("expected non-nil HTTP handler for prometheus backend")
	}
}

func TestInitializeNoop(t *testing.T) {
	initNoop(t)
	// All Record* functions must not panic when noop backend is active.
	metrics.RecordRestart()
	metrics.RecordHTTPRequest("/test", "GET", "200")
	metrics.RecordSNIConnection("accepted")
	metrics.RecordPeersTotal("wg0", 1)
}

func TestDefaultConfig(t *testing.T) {
	cfg := metrics.DefaultConfig()
	if cfg.Backend != "prometheus" {
		t.Errorf("expected prometheus default backend, got %q", cfg.Backend)
	}
}

func TestShutdownNoInit(t *testing.T) {
	// Shutdown without Initialize should not panic or error.
	if err := metrics.Shutdown(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecordHTTPRequest(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordHTTPRequest("/peers", "POST", "201")
	body := scrape(t, h)
	assertContains(t, body, "gerbil_http_requests_total")
}

func TestRecordHTTPRequestDuration(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordHTTPRequestDuration("/peers", "POST", 0.05)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_http_request_duration_seconds")
}

func TestRecordInterfaceUp(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordInterfaceUp("wg0", "host1", true)
	metrics.RecordInterfaceUp("wg0", "host1", false)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_wg_interface_up")
}

func TestRecordPeersTotal(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordPeersTotal("wg0", 3)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_wg_peers_total")
}

func TestRecordBytesReceivedTransmitted(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordBytesReceived("wg0", "peer1", 1024)
	metrics.RecordBytesTransmitted("wg0", "peer1", 512)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_wg_bytes_received_total")
	assertContains(t, body, "gerbil_wg_bytes_transmitted_total")
}

func TestRecordSNI(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordSNIConnection("accepted")
	metrics.RecordSNIActiveConnection(1)
	metrics.RecordSNIConnectionDuration(1.5)
	metrics.RecordSNIRouteCacheHit("hit")
	metrics.RecordSNIRouteAPIRequest("success")
	metrics.RecordSNIRouteAPILatency(0.01)
	metrics.RecordSNILocalOverride("yes")
	metrics.RecordSNITrustedProxyEvent("proxy_protocol_parsed")
	metrics.RecordSNIProxyProtocolParseError()
	metrics.RecordSNIDataBytes("client_to_target", 2048)
	metrics.RecordSNITunnelTermination("eof")
	body := scrape(t, h)
	assertContains(t, body, "gerbil_sni_connections_total")
	assertContains(t, body, "gerbil_sni_active_connections")
}

func TestRecordRelay(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordUDPPacket("relay", "data", "in")
	metrics.RecordUDPPacketSize("relay", "data", 256)
	metrics.RecordHolePunchEvent("relay", "success")
	metrics.RecordProxyMapping("relay", 1)
	metrics.RecordSession("relay", 1)
	metrics.RecordSessionRebuilt("relay")
	metrics.RecordCommPattern("relay", 1)
	metrics.RecordProxyCleanupRemoved("relay", "session", 2)
	metrics.RecordProxyConnectionError("relay", "dial_udp")
	metrics.RecordProxyInitialMappings("relay", 5)
	metrics.RecordProxyMappingUpdate("relay")
	metrics.RecordProxyIdleCleanupDuration("relay", "conn", 0.1)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_udp_packets_total")
	assertContains(t, body, "gerbil_proxy_mapping_active")
}

func TestRecordWireGuard(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordHandshake("wg0", "peer1", "success")
	metrics.RecordHandshakeLatency("wg0", "peer1", 0.02)
	metrics.RecordPeerRTT("wg0", "peer1", 0.005)
	metrics.RecordPeerConnected("wg0", "peer1", true)
	metrics.RecordAllowedIPsCount("wg0", "peer1", 2)
	metrics.RecordKeyRotation("wg0", "scheduled")
	body := scrape(t, h)
	assertContains(t, body, "gerbil_wg_handshakes_total")
	assertContains(t, body, "gerbil_wg_peer_connected")
}

func TestRecordHousekeeping(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordRemoteConfigFetch("success")
	metrics.RecordBandwidthReport("success")
	metrics.RecordPeerBandwidthBytes("peer1", "rx", 512)
	metrics.RecordMemorySpike("warning")
	metrics.RecordHeapProfileWritten()
	body := scrape(t, h)
	assertContains(t, body, "gerbil_remote_config_fetches_total")
	assertContains(t, body, "gerbil_memory_spike_total")
}

func TestRecordOperational(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordConfigReload("success")
	metrics.RecordRestart()
	metrics.RecordAuthFailure("peer1", "bad_key")
	metrics.RecordACLDenied("wg0", "peer1", "default-deny")
	metrics.RecordCertificateExpiry(exampleHostname, "wg0", 90.0)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_config_reloads_total")
	assertContains(t, body, "gerbil_restart_total")
}

func TestRecordNetlink(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordNetlinkEvent("link_up")
	metrics.RecordNetlinkError("wg", "timeout")
	metrics.RecordSyncDuration("config", 0.1)
	metrics.RecordWorkqueueDepth("main", 3)
	metrics.RecordKernelModuleLoad("success")
	metrics.RecordFirewallRuleApplied("success", "INPUT")
	metrics.RecordActiveSession("wg0", 1)
	metrics.RecordActiveProxyConnection(exampleHostname, 1)
	metrics.RecordProxyRouteLookup("hit", exampleHostname)
	metrics.RecordProxyTLSHandshake(exampleHostname, 0.05)
	metrics.RecordProxyBytesTransmitted(exampleHostname, "tx", 1024)
	body := scrape(t, h)
	assertContains(t, body, "gerbil_netlink_events_total")
	assertContains(t, body, "gerbil_active_sessions")
}

func TestRecordPeerOperation(t *testing.T) {
	h := initPrometheus(t)
	metrics.RecordPeerOperation("add", "success")
	metrics.RecordProxyMappingUpdateRequest("success")
	metrics.RecordDestinationsUpdateRequest("success")
	body := scrape(t, h)
	assertContains(t, body, "gerbil_peer_operations_total")
}

func TestInitializeInvalidBackend(t *testing.T) {
	cfg := observability.MetricsConfig{Enabled: true, Backend: "invalid"}
	_, err := metrics.Initialize(cfg)
	if err == nil {
		t.Error("expected error for invalid backend")
	}
}

func TestInitializeBackendNone(t *testing.T) {
	cfg := metrics.DefaultConfig()
	cfg.Backend = "none"
	h, err := metrics.Initialize(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != nil {
		t.Error("none backend should return nil handler")
	}
	// All Record* calls should be noop
	metrics.RecordRestart()
	metrics.Shutdown(context.Background()) //nolint:errcheck
}
