<!-- markdownlint-disable MD036 MD060 -->
# Gerbil Observability Architecture

This document describes the metrics subsystem for Gerbil, explains the design
decisions, and shows how to configure each backend.

---

## Architecture Overview

Gerbil's metrics subsystem uses a **pluggable backend** design:

```text
main.go  ─── internal/metrics  ─── internal/observability  ─── backend
                 (facade)                 (interface)           Prometheus
                                                           OR   OTel/OTLP
                                                           OR   Noop (disabled)
```

Application code (main, relay, proxy) calls only the `metrics.Record*`
functions in `internal/metrics`. That package delegates to whichever backend
was selected at startup via `internal/observability.Backend`.

### Why Prometheus-native and OTel are mutually exclusive

**Exactly one** metrics backend may be active at runtime:

| Mode | What happens |
|------|-------------|
| `prometheus` | Native Prometheus client registers metrics on a dedicated registry and exposes `/metrics`. No OTel SDK is initialised. |
| `otel` | OTel SDK pushes metrics via OTLP/gRPC or OTLP/HTTP to an external collector. No `/metrics` endpoint is exposed. |
| `none` | A safe noop backend is used. All `Record*` calls are discarded. |

Running both simultaneously would mean every metric is recorded twice through
two different code paths, with differing semantics (pull vs. push, different
naming rules, different cardinality handling). The design enforces a single
source of truth.

### Future OTel tracing and logging

The `internal/observability/otel/` package is designed so that tracing and
logging support can be added **beside** the existing metrics code without
touching the Prometheus-native path:

```bash
internal/observability/otel/
  backend.go     ← metrics
  exporter.go    ← OTLP exporter creation
  resource.go    ← OTel resource
  trace.go       ← future: TracerProvider setup
  log.go         ← future: LoggerProvider setup
```

---

## Configuration

### Config precedence

1. CLI flags (highest priority)
2. Environment variables
3. Defaults

### Config struct

```go
type MetricsConfig struct {
    Enabled               bool
    Backend               string // "prometheus" | "otel" | "none"
    Prometheus            PrometheusConfig
    OTel                  OTelConfig
    ServiceName           string
    ServiceVersion        string
    DeploymentEnvironment string
}

type PrometheusConfig struct {
    Path string // default: "/metrics"
}

type OTelConfig struct {
    Protocol       string        // "grpc" (default) or "http"
    Endpoint       string        // default: "localhost:4317"
    Insecure       bool          // default: true
    ExportInterval time.Duration // default: 60s
}
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLED` | `true` | Enable/disable metrics |
| `METRICS_BACKEND` | `prometheus` | Backend: `prometheus`, `otel`, or `none` |
| `METRICS_PATH` | `/metrics` | HTTP path for Prometheus endpoint |
| `OTEL_METRICS_PROTOCOL` | `grpc` | OTLP transport: `grpc` or `http` |
| `OTEL_METRICS_ENDPOINT` | `localhost:4317` | OTLP collector address |
| `OTEL_METRICS_INSECURE` | `true` | Disable TLS for OTLP |
| `OTEL_METRICS_EXPORT_INTERVAL` | `60s` | Push interval (e.g. `10s`, `1m`) |
| `DEPLOYMENT_ENVIRONMENT` | _(unset)_ | OTel deployment.environment attribute |

### CLI flags

```bash
--metrics-enabled            bool    (default: true)
--metrics-backend            string  (default: prometheus)
--metrics-path               string  (default: /metrics)
--otel-metrics-protocol      string  (default: grpc)
--otel-metrics-endpoint      string  (default: localhost:4317)
--otel-metrics-insecure      bool    (default: true)
--otel-metrics-export-interval  duration  (default: 1m0s)
```

---

## When to choose each backend

| Criterion | Prometheus | OTel/OTLP |
|-----------|-----------|-----------|
| Existing Prometheus/Grafana stack | ✅ | |
| Pull-based scraping | ✅ | |
| No external collector required | ✅ | |
| Vendor-neutral telemetry | | ✅ |
| Push-based export | | ✅ |
| Grafana Cloud / managed OTLP | | ✅ |
| Future traces + logs via same pipeline | | ✅ |

---

## Enabling Prometheus-native mode

### Environment variables

```bash
METRICS_ENABLED=true
METRICS_BACKEND=prometheus
METRICS_PATH=/metrics
```

### CLI

```bash
./gerbil --metrics-enabled --metrics-backend=prometheus --metrics-path=/metrics \
         --config=/etc/gerbil/config.json
```

The metrics config is supplied separately via env/flags; it is not embedded
in the WireGuard config file.

The Prometheus `/metrics` endpoint is registered only when
`--metrics-backend=prometheus`. All gerbil_* metrics plus Go runtime metrics
are available.

---

## Enabling OTel mode

### Environment variables

```bash
export METRICS_ENABLED=true
export METRICS_BACKEND=otel
export OTEL_METRICS_PROTOCOL=grpc
export OTEL_METRICS_ENDPOINT=otel-collector:4317
export OTEL_METRICS_INSECURE=true
export OTEL_METRICS_EXPORT_INTERVAL=10s
export DEPLOYMENT_ENVIRONMENT=production
```

### CLI

```bash
./gerbil --metrics-enabled \
         --metrics-backend=otel \
         --otel-metrics-protocol=grpc \
         --otel-metrics-endpoint=otel-collector:4317 \
         --otel-metrics-insecure \
         --otel-metrics-export-interval=10s \
         --config=/etc/gerbil/config.json
```

### HTTP mode (OTLP/HTTP)

```bash
export OTEL_METRICS_PROTOCOL=http
export OTEL_METRICS_ENDPOINT=otel-collector:4318
```

---

## Disabling metrics

```bash
export METRICS_ENABLED=false
# or
./gerbil --metrics-enabled=false
# or
./gerbil --metrics-backend=none
```

When disabled, all `Record*` calls are directed to a safe noop backend that
discards observations without allocating or locking.

---

## Metric catalog

All metrics use the prefix `gerbil_<component>_<name>`.

### WireGuard metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gerbil_wg_interface_up` | Gauge | `ifname`, `instance` | 1=up, 0=down |
| `gerbil_wg_peers_total` | UpDownCounter | `ifname` | Configured peers |
| `gerbil_wg_peer_connected` | Gauge | `ifname`, `peer` | 1=connected, 0=disconnected |
| `gerbil_wg_bytes_received_total` | Counter | `ifname`, `peer` | Bytes received |
| `gerbil_wg_bytes_transmitted_total` | Counter | `ifname`, `peer` | Bytes transmitted |
| `gerbil_wg_handshakes_total` | Counter | `ifname`, `peer`, `result` | Handshake attempts |
| `gerbil_wg_handshake_latency_seconds` | Histogram | `ifname`, `peer` | Handshake duration |
| `gerbil_wg_peer_rtt_seconds` | Histogram | `ifname`, `peer` | Peer round-trip time |

### Relay metrics

| Metric | Type | Labels |
|--------|------|--------|
| `gerbil_proxy_mapping_active` | UpDownCounter | `ifname` |
| `gerbil_session_active` | UpDownCounter | `ifname` |
| `gerbil_active_sessions` | UpDownCounter | `ifname` |
| `gerbil_udp_packets_total` | Counter | `ifname`, `type`, `direction` |
| `gerbil_hole_punch_events_total` | Counter | `ifname`, `result` |

### SNI proxy metrics

| Metric | Type | Labels |
|--------|------|--------|
| `gerbil_sni_connections_total` | Counter | `result` |
| `gerbil_sni_active_connections` | UpDownCounter | _(none)_ |
| `gerbil_sni_route_cache_hits_total` | Counter | `result` |
| `gerbil_sni_route_api_requests_total` | Counter | `result` |
| `gerbil_proxy_route_lookups_total` | Counter | `result`, `hostname` |

### HTTP metrics

| Metric | Type | Labels |
|--------|------|--------|
| `gerbil_http_requests_total` | Counter | `endpoint`, `method`, `status_code` |
| `gerbil_http_request_duration_seconds` | Histogram | `endpoint`, `method` |

---

## Using Docker Compose

The `docker-compose.metrics.yml` provides a complete observability stack.

**Prometheus mode:**

```bash
METRICS_BACKEND=prometheus docker-compose -f docker-compose.metrics.yml up -d
# Scrape at http://localhost:3003/metrics
# Grafana at http://localhost:3000 (admin/admin)
```

**OTel mode:**

```bash
METRICS_BACKEND=otel OTEL_METRICS_ENDPOINT=otel-collector:4317 \
  docker-compose -f docker-compose.metrics.yml up -d
```
