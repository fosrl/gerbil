// Package metrics provides the application-level metrics facade for Gerbil.
//
// Application code (main, relay, proxy) uses only the Record* functions in this
// package. The actual recording is delegated to the backend selected in
// internal/observability. Neither Prometheus nor OTel packages are imported here.
package metrics

import (
	"context"
	"net/http"

	"github.com/fosrl/gerbil/internal/observability"
)

// Config is the metrics configuration type. It is an alias for
// observability.MetricsConfig so callers do not need to import observability.
type Config = observability.MetricsConfig

// PrometheusConfig is re-exported for convenience.
type PrometheusConfig = observability.PrometheusConfig

// OTelConfig is re-exported for convenience.
type OTelConfig = observability.OTelConfig

var (
	backend observability.Backend

	// Interface and peer metrics
	wgInterfaceUp      observability.Int64Gauge
	wgPeersTotal       observability.UpDownCounter
	wgPeerConnected    observability.Int64Gauge
	wgHandshakesTotal  observability.Counter
	wgHandshakeLatency observability.Histogram
	wgPeerRTT          observability.Histogram
	wgBytesReceived    observability.Counter
	wgBytesTransmitted observability.Counter
	allowedIPsCount    observability.UpDownCounter
	keyRotationTotal   observability.Counter

	// System and proxy metrics
	netlinkEventsTotal     observability.Counter
	netlinkErrorsTotal     observability.Counter
	syncDuration           observability.Histogram
	workqueueDepth         observability.UpDownCounter
	kernelModuleLoads      observability.Counter
	firewallRulesApplied   observability.Counter
	activeSessions         observability.UpDownCounter
	activeProxyConnections observability.UpDownCounter
	proxyRouteLookups      observability.Counter
	proxyTLSHandshake      observability.Histogram
	proxyBytesTransmitted  observability.Counter

	// UDP Relay / Proxy Metrics
	udpPacketsTotal            observability.Counter
	udpPacketSizeBytes         observability.Histogram
	holePunchEventsTotal       observability.Counter
	proxyMappingActive         observability.UpDownCounter
	sessionActive              observability.UpDownCounter
	sessionRebuiltTotal        observability.Counter
	commPatternActive          observability.UpDownCounter
	proxyCleanupRemovedTotal   observability.Counter
	proxyConnectionErrorsTotal observability.Counter
	proxyInitialMappingsTotal  observability.Int64Gauge
	proxyMappingUpdatesTotal   observability.Counter
	proxyIdleCleanupDuration   observability.Histogram

	// SNI Proxy Metrics
	sniConnectionsTotal              observability.Counter
	sniConnectionDuration            observability.Histogram
	sniActiveConnections             observability.UpDownCounter
	sniRouteCacheHitsTotal           observability.Counter
	sniRouteAPIRequestsTotal         observability.Counter
	sniRouteAPILatency               observability.Histogram
	sniLocalOverrideTotal            observability.Counter
	sniTrustedProxyEventsTotal       observability.Counter
	sniProxyProtocolParseErrorsTotal observability.Counter
	sniDataBytesTotal                observability.Counter
	sniTunnelTerminationsTotal       observability.Counter

	// HTTP API & Peer Management Metrics
	httpRequestsTotal               observability.Counter
	httpRequestDuration             observability.Histogram
	peerOperationsTotal             observability.Counter
	proxyMappingUpdateRequestsTotal observability.Counter
	destinationsUpdateRequestsTotal observability.Counter

	// Remote Configuration, Reporting & Housekeeping
	remoteConfigFetchesTotal observability.Counter
	bandwidthReportsTotal    observability.Counter
	peerBandwidthBytesTotal  observability.Counter
	memorySpikeTotal         observability.Counter
	heapProfilesWrittenTotal observability.Counter

	// Operational metrics
	configReloadsTotal    observability.Counter
	restartTotal          observability.Counter
	authFailuresTotal     observability.Counter
	aclDeniedTotal        observability.Counter
	certificateExpiryDays observability.Float64Gauge
)

// DefaultConfig returns a default metrics configuration.
func DefaultConfig() Config {
	return observability.DefaultMetricsConfig()
}

// Initialize sets up the metrics system using the selected backend.
// It returns the /metrics HTTP handler (non-nil only for Prometheus backend).
func Initialize(cfg Config) (http.Handler, error) {
	b, err := observability.New(cfg)
	if err != nil {
		return nil, err
	}
	backend = b

	if err := createInstruments(); err != nil {
		return nil, err
	}

	return backend.HTTPHandler(), nil
}

// Shutdown gracefully shuts down the metrics backend.
func Shutdown(ctx context.Context) error {
	if backend != nil {
		return backend.Shutdown(ctx)
	}
	return nil
}

func createInstruments() error {
	durationBuckets := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	sizeBuckets := []float64{512, 1024, 4096, 16384, 65536, 262144, 1048576}
	sniDurationBuckets := []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

	b := backend

	wgInterfaceUp = b.NewInt64Gauge("gerbil_wg_interface_up",
		"Operational state of a WireGuard interface (1=up, 0=down)", "ifname", "instance")
	wgPeersTotal = b.NewUpDownCounter("gerbil_wg_peers_total",
		"Total number of configured peers per interface", "ifname")
	wgPeerConnected = b.NewInt64Gauge("gerbil_wg_peer_connected",
		"Whether a specific peer is connected (1=connected, 0=disconnected)", "ifname", "peer")
	allowedIPsCount = b.NewUpDownCounter("gerbil_allowed_ips_count",
		"Number of allowed IPs configured per peer", "ifname", "peer")
	keyRotationTotal = b.NewCounter("gerbil_key_rotation_total",
		"Key rotation events", "ifname", "reason")
	wgHandshakesTotal = b.NewCounter("gerbil_wg_handshakes_total",
		"Count of handshake attempts with their result status", "ifname", "peer", "result")
	wgHandshakeLatency = b.NewHistogram("gerbil_wg_handshake_latency_seconds",
		"Distribution of handshake latencies in seconds", durationBuckets, "ifname", "peer")
	wgPeerRTT = b.NewHistogram("gerbil_wg_peer_rtt_seconds",
		"Observed round-trip time to a peer in seconds", durationBuckets, "ifname", "peer")
	wgBytesReceived = b.NewCounter("gerbil_wg_bytes_received_total",
		"Number of bytes received from a peer", "ifname", "peer")
	wgBytesTransmitted = b.NewCounter("gerbil_wg_bytes_transmitted_total",
		"Number of bytes transmitted to a peer", "ifname", "peer")
	netlinkEventsTotal = b.NewCounter("gerbil_netlink_events_total",
		"Number of netlink events processed", "event_type")
	netlinkErrorsTotal = b.NewCounter("gerbil_netlink_errors_total",
		"Count of netlink or kernel errors", "component", "error_type")
	syncDuration = b.NewHistogram("gerbil_sync_duration_seconds",
		"Duration of reconciliation/sync loops in seconds", durationBuckets, "component")
	workqueueDepth = b.NewUpDownCounter("gerbil_workqueue_depth",
		"Current length of internal work queues", "queue")
	kernelModuleLoads = b.NewCounter("gerbil_kernel_module_loads_total",
		"Count of kernel module load attempts", "result")
	firewallRulesApplied = b.NewCounter("gerbil_firewall_rules_applied_total",
		"IPTables/NFT rules applied", "result", "chain")
	activeSessions = b.NewUpDownCounter("gerbil_active_sessions",
		"Number of active UDP relay sessions", "ifname")
	activeProxyConnections = b.NewUpDownCounter("gerbil_active_proxy_connections",
		"Active SNI proxy connections")
	proxyRouteLookups = b.NewCounter("gerbil_proxy_route_lookups_total",
		"Number of route lookups", "result")
	proxyTLSHandshake = b.NewHistogram("gerbil_proxy_tls_handshake_seconds",
		"TLS handshake duration for SNI proxy in seconds", durationBuckets)
	proxyBytesTransmitted = b.NewCounter("gerbil_proxy_bytes_transmitted_total",
		"Bytes sent/received by the SNI proxy", "direction")
	configReloadsTotal = b.NewCounter("gerbil_config_reloads_total",
		"Number of configuration reloads", "result")
	restartTotal = b.NewCounter("gerbil_restart_total",
		"Process restart count")
	authFailuresTotal = b.NewCounter("gerbil_auth_failures_total",
		"Count of authentication or peer validation failures", "peer", "reason")
	aclDeniedTotal = b.NewCounter("gerbil_acl_denied_total",
		"Access control denied events", "ifname", "peer", "policy")
	certificateExpiryDays = b.NewFloat64Gauge("gerbil_certificate_expiry_days",
		"Days until certificate expiry", "cert_name", "ifname")
	udpPacketsTotal = b.NewCounter("gerbil_udp_packets_total",
		"Count of UDP packets processed by relay workers", "ifname", "type", "direction")
	udpPacketSizeBytes = b.NewHistogram("gerbil_udp_packet_size_bytes",
		"Size distribution of packets forwarded through relay", sizeBuckets, "ifname", "type")
	holePunchEventsTotal = b.NewCounter("gerbil_hole_punch_events_total",
		"Count of hole punch messages processed", "ifname", "result")
	proxyMappingActive = b.NewUpDownCounter("gerbil_proxy_mapping_active",
		"Number of active proxy mappings", "ifname")
	sessionActive = b.NewUpDownCounter("gerbil_session_active",
		"Number of active WireGuard sessions", "ifname")
	sessionRebuiltTotal = b.NewCounter("gerbil_session_rebuilt_total",
		"Count of sessions rebuilt from communication patterns", "ifname")
	commPatternActive = b.NewUpDownCounter("gerbil_comm_pattern_active",
		"Number of active communication patterns", "ifname")
	proxyCleanupRemovedTotal = b.NewCounter("gerbil_proxy_cleanup_removed_total",
		"Count of items removed during cleanup routines", "ifname", "component")
	proxyConnectionErrorsTotal = b.NewCounter("gerbil_proxy_connection_errors_total",
		"Count of connection errors in proxy operations", "ifname", "error_type")
	proxyInitialMappingsTotal = b.NewInt64Gauge("gerbil_proxy_initial_mappings",
		"Number of initial proxy mappings loaded", "ifname")
	proxyMappingUpdatesTotal = b.NewCounter("gerbil_proxy_mapping_updates_total",
		"Count of proxy mapping updates", "ifname")
	proxyIdleCleanupDuration = b.NewHistogram("gerbil_proxy_idle_cleanup_duration_seconds",
		"Duration of cleanup cycles", durationBuckets, "ifname", "component")
	sniConnectionsTotal = b.NewCounter("gerbil_sni_connections_total",
		"Count of connections processed by SNI proxy", "result")
	sniConnectionDuration = b.NewHistogram("gerbil_sni_connection_duration_seconds",
		"Lifetime distribution of proxied TLS connections", sniDurationBuckets)
	sniActiveConnections = b.NewUpDownCounter("gerbil_sni_active_connections",
		"Number of active SNI tunnels")
	sniRouteCacheHitsTotal = b.NewCounter("gerbil_sni_route_cache_hits_total",
		"Count of route cache hits and misses", "result")
	sniRouteAPIRequestsTotal = b.NewCounter("gerbil_sni_route_api_requests_total",
		"Count of route API requests", "result")
	sniRouteAPILatency = b.NewHistogram("gerbil_sni_route_api_latency_seconds",
		"Distribution of route API call latencies", durationBuckets)
	sniLocalOverrideTotal = b.NewCounter("gerbil_sni_local_override_total",
		"Count of routes using local overrides", "hit")
	sniTrustedProxyEventsTotal = b.NewCounter("gerbil_sni_trusted_proxy_events_total",
		"Count of PROXY protocol events", "event")
	sniProxyProtocolParseErrorsTotal = b.NewCounter("gerbil_sni_proxy_protocol_parse_errors_total",
		"Count of PROXY protocol parse failures")
	sniDataBytesTotal = b.NewCounter("gerbil_sni_data_bytes_total",
		"Count of bytes proxied through SNI tunnels", "direction")
	sniTunnelTerminationsTotal = b.NewCounter("gerbil_sni_tunnel_terminations_total",
		"Count of tunnel terminations by reason", "reason")
	httpRequestsTotal = b.NewCounter("gerbil_http_requests_total",
		"Count of HTTP requests to management API", "endpoint", "method", "status_code")
	httpRequestDuration = b.NewHistogram("gerbil_http_request_duration_seconds",
		"Distribution of HTTP request handling time", durationBuckets, "endpoint", "method")
	peerOperationsTotal = b.NewCounter("gerbil_peer_operations_total",
		"Count of peer lifecycle operations", "operation", "result")
	proxyMappingUpdateRequestsTotal = b.NewCounter("gerbil_proxy_mapping_update_requests_total",
		"Count of proxy mapping update API calls", "result")
	destinationsUpdateRequestsTotal = b.NewCounter("gerbil_destinations_update_requests_total",
		"Count of destinations update API calls", "result")
	remoteConfigFetchesTotal = b.NewCounter("gerbil_remote_config_fetches_total",
		"Count of remote configuration fetch attempts", "result")
	bandwidthReportsTotal = b.NewCounter("gerbil_bandwidth_reports_total",
		"Count of bandwidth report transmissions", "result")
	peerBandwidthBytesTotal = b.NewCounter("gerbil_peer_bandwidth_bytes_total",
		"Bytes per peer tracked by bandwidth calculation", "peer", "direction")
	memorySpikeTotal = b.NewCounter("gerbil_memory_spike_total",
		"Count of memory spikes detected", "severity")
	heapProfilesWrittenTotal = b.NewCounter("gerbil_heap_profiles_written_total",
		"Count of heap profile files generated")

	return nil
}

func RecordInterfaceUp(ifname, instance string, up bool) {
	value := int64(0)
	if up {
		value = 1
	}
	wgInterfaceUp.Record(context.Background(), value, observability.Labels{"ifname": ifname, "instance": instance})
}

func RecordPeersTotal(ifname string, delta int64) {
	wgPeersTotal.Add(context.Background(), delta, observability.Labels{"ifname": ifname})
}

func RecordPeerConnected(ifname, peer string, connected bool) {
	value := int64(0)
	if connected {
		value = 1
	}
	wgPeerConnected.Record(context.Background(), value, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordHandshake(ifname, peer, result string) {
	wgHandshakesTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "peer": peer, "result": result})
}

func RecordHandshakeLatency(ifname, peer string, seconds float64) {
	wgHandshakeLatency.Record(context.Background(), seconds, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordPeerRTT(ifname, peer string, seconds float64) {
	wgPeerRTT.Record(context.Background(), seconds, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordBytesReceived(ifname, peer string, bytes int64) {
	wgBytesReceived.Add(context.Background(), bytes, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordBytesTransmitted(ifname, peer string, bytes int64) {
	wgBytesTransmitted.Add(context.Background(), bytes, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordAllowedIPsCount(ifname, peer string, delta int64) {
	allowedIPsCount.Add(context.Background(), delta, observability.Labels{"ifname": ifname, "peer": peer})
}

func RecordKeyRotation(ifname, reason string) {
	keyRotationTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "reason": reason})
}

func RecordNetlinkEvent(eventType string) {
	netlinkEventsTotal.Add(context.Background(), 1, observability.Labels{"event_type": eventType})
}

func RecordNetlinkError(component, errorType string) {
	netlinkErrorsTotal.Add(context.Background(), 1, observability.Labels{"component": component, "error_type": errorType})
}

func RecordSyncDuration(component string, seconds float64) {
	syncDuration.Record(context.Background(), seconds, observability.Labels{"component": component})
}

func RecordWorkqueueDepth(queue string, delta int64) {
	workqueueDepth.Add(context.Background(), delta, observability.Labels{"queue": queue})
}

func RecordKernelModuleLoad(result string) {
	kernelModuleLoads.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordFirewallRuleApplied(result, chain string) {
	firewallRulesApplied.Add(context.Background(), 1, observability.Labels{"result": result, "chain": chain})
}

func RecordActiveSession(ifname string, delta int64) {
	activeSessions.Add(context.Background(), delta, observability.Labels{"ifname": ifname})
}

func RecordActiveProxyConnection(hostname string, delta int64) {
	_ = hostname
	activeProxyConnections.Add(context.Background(), delta, nil)
}

func RecordProxyRouteLookup(result, hostname string) {
	_ = hostname
	proxyRouteLookups.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordProxyTLSHandshake(hostname string, seconds float64) {
	_ = hostname
	proxyTLSHandshake.Record(context.Background(), seconds, nil)
}

func RecordProxyBytesTransmitted(hostname, direction string, bytes int64) {
	_ = hostname
	proxyBytesTransmitted.Add(context.Background(), bytes, observability.Labels{"direction": direction})
}

func RecordConfigReload(result string) {
	configReloadsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordRestart() {
	restartTotal.Add(context.Background(), 1, nil)
}

func RecordAuthFailure(peer, reason string) {
	authFailuresTotal.Add(context.Background(), 1, observability.Labels{"peer": peer, "reason": reason})
}

func RecordACLDenied(ifname, peer, policy string) {
	aclDeniedTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "peer": peer, "policy": policy})
}

func RecordCertificateExpiry(certName, ifname string, days float64) {
	certificateExpiryDays.Record(context.Background(), days, observability.Labels{"cert_name": certName, "ifname": ifname})
}

func RecordUDPPacket(ifname, packetType, direction string) {
	udpPacketsTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "type": packetType, "direction": direction})
}

func RecordUDPPacketSize(ifname, packetType string, bytes float64) {
	udpPacketSizeBytes.Record(context.Background(), bytes, observability.Labels{"ifname": ifname, "type": packetType})
}

func RecordHolePunchEvent(ifname, result string) {
	holePunchEventsTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "result": result})
}

func RecordProxyMapping(ifname string, delta int64) {
	proxyMappingActive.Add(context.Background(), delta, observability.Labels{"ifname": ifname})
}

func RecordSession(ifname string, delta int64) {
	sessionActive.Add(context.Background(), delta, observability.Labels{"ifname": ifname})
}

func RecordSessionRebuilt(ifname string) {
	sessionRebuiltTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname})
}

func RecordCommPattern(ifname string, delta int64) {
	commPatternActive.Add(context.Background(), delta, observability.Labels{"ifname": ifname})
}

func RecordProxyCleanupRemoved(ifname, component string, count int64) {
	proxyCleanupRemovedTotal.Add(context.Background(), count, observability.Labels{"ifname": ifname, "component": component})
}

func RecordProxyConnectionError(ifname, errorType string) {
	proxyConnectionErrorsTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname, "error_type": errorType})
}

func RecordProxyInitialMappings(ifname string, count int64) {
	proxyInitialMappingsTotal.Record(context.Background(), count, observability.Labels{"ifname": ifname})
}

func RecordProxyMappingUpdate(ifname string) {
	proxyMappingUpdatesTotal.Add(context.Background(), 1, observability.Labels{"ifname": ifname})
}

func RecordProxyIdleCleanupDuration(ifname, component string, seconds float64) {
	proxyIdleCleanupDuration.Record(context.Background(), seconds, observability.Labels{"ifname": ifname, "component": component})
}

func RecordSNIConnection(result string) {
	sniConnectionsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordSNIConnectionDuration(seconds float64) {
	sniConnectionDuration.Record(context.Background(), seconds, nil)
}

func RecordSNIActiveConnection(delta int64) {
	sniActiveConnections.Add(context.Background(), delta, nil)
}

func RecordSNIRouteCacheHit(result string) {
	sniRouteCacheHitsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordSNIRouteAPIRequest(result string) {
	sniRouteAPIRequestsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordSNIRouteAPILatency(seconds float64) {
	sniRouteAPILatency.Record(context.Background(), seconds, nil)
}

func RecordSNILocalOverride(hit string) {
	sniLocalOverrideTotal.Add(context.Background(), 1, observability.Labels{"hit": hit})
}

func RecordSNITrustedProxyEvent(event string) {
	sniTrustedProxyEventsTotal.Add(context.Background(), 1, observability.Labels{"event": event})
}

func RecordSNIProxyProtocolParseError() {
	sniProxyProtocolParseErrorsTotal.Add(context.Background(), 1, nil)
}

func RecordSNIDataBytes(direction string, bytes int64) {
	sniDataBytesTotal.Add(context.Background(), bytes, observability.Labels{"direction": direction})
}

func RecordSNITunnelTermination(reason string) {
	sniTunnelTerminationsTotal.Add(context.Background(), 1, observability.Labels{"reason": reason})
}

func RecordHTTPRequest(endpoint, method, statusCode string) {
	httpRequestsTotal.Add(context.Background(), 1, observability.Labels{"endpoint": endpoint, "method": method, "status_code": statusCode})
}

func RecordHTTPRequestDuration(endpoint, method string, seconds float64) {
	httpRequestDuration.Record(context.Background(), seconds, observability.Labels{"endpoint": endpoint, "method": method})
}

func RecordPeerOperation(operation, result string) {
	peerOperationsTotal.Add(context.Background(), 1, observability.Labels{"operation": operation, "result": result})
}

func RecordProxyMappingUpdateRequest(result string) {
	proxyMappingUpdateRequestsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordDestinationsUpdateRequest(result string) {
	destinationsUpdateRequestsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordRemoteConfigFetch(result string) {
	remoteConfigFetchesTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordBandwidthReport(result string) {
	bandwidthReportsTotal.Add(context.Background(), 1, observability.Labels{"result": result})
}

func RecordPeerBandwidthBytes(peer, direction string, bytes int64) {
	peerBandwidthBytesTotal.Add(context.Background(), bytes, observability.Labels{"peer": peer, "direction": direction})
}

func RecordMemorySpike(severity string) {
	memorySpikeTotal.Add(context.Background(), 1, observability.Labels{"severity": severity})
}

func RecordHeapProfileWritten() {
	heapProfilesWrittenTotal.Add(context.Background(), 1, nil)
}
