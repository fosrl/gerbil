# Gerbil

Gerbil is a simple [WireGuard](https://www.wireguard.com/) interface management server written in Go. Gerbil makes it easy to create WireGuard interfaces as well as add and remove peers with an HTTP API.

### Installation and Documentation

Gerbil works with Pangolin, Newt, and Olm as part of the larger system. See documentation below:

-   [Full Documentation](https://docs.pangolin.net)

## Key Functions

### Setup WireGuard

A WireGuard interface will be created and configured on the local Linux machine or in the Docker container according to the values given in either a JSON config file or via the remote server. If the interface already exists, it will be reconfigured.

### Manage Peers

Gerbil will create the peers defined in the config on the WireGuard interface. The HTTP API can be used to remove, create, and update peers on the interface dynamically.

### Report Bandwidth

Bytes transmitted in and out of each peer are collected every 10 seconds, and incremental usage is reported via the api endpoint. This can be used to track data usage of each peer on the remote server.

### Handle client relaying

Gerbil listens on port 21820 for incoming UDP hole punch packets to orchestrate NAT hole punching between olm and newt clients. Additionally, it handles relaying data through the gerbil server down to the newt. This is accomplished by scanning each packet for headers and handling them appropriately.

### SNI Proxy

Gerbil includes an SNI (Server Name Indication) proxy that enables intelligent routing of HTTPS traffic between Pangolin nodes. When a TLS connection comes in, the proxy extracts the hostname from the SNI extension and queries Pangolin to determine the correct routing destination. This allows seamless routing of web traffic through the WireGuard mesh network:

- If the hostname is configured for local handling (via local overrides or local SNIs), traffic is routed to the local proxy
- Otherwise, the proxy queries Pangolin's routing API to determine which node should handle the traffic
- Supports caching of routing decisions to improve performance
- Handles connection pooling and graceful shutdown
- Optional PROXY protocol v1 support to preserve original client IP addresses when forwarding to downstream proxies (HAProxy, Nginx, etc.)

The PROXY protocol allows downstream proxies to know the real client IP address instead of seeing the SNI proxy's IP. When enabled with `--proxy-protocol`, the SNI proxy will prepend a PROXY protocol header to each connection containing the original client's IP and port information.

In single node (self hosted) Pangolin deployments this can be bypassed by using port 443:443 to route to Traefik instead of the SNI proxy at 8443.

### Observability with OpenTelemetry

Gerbil includes comprehensive OpenTelemetry metrics instrumentation for monitoring and observability. Metrics can be exported via:

- **Prometheus**: Pull-based metrics at the `/metrics` endpoint (enabled by default)
- **OTLP**: Push-based metrics to any OpenTelemetry-compatible collector

Key metrics include:

- WireGuard interface and peer status
- Bandwidth usage per peer
- Active relay sessions and proxy connections
- Handshake success/failure rates
- Route lookup cache hit/miss ratios
- Go runtime metrics (GC, goroutines, memory)

See [docs/observability.md](docs/observability.md) for complete documentation, metrics reference, and examples.

## CLI Args

Important:
- `reachableAt`: How should the remote server reach Gerbil's API?
- `generateAndSaveKeyTo`: Where to save the generated WireGuard private key to persist across restarts.
- `remoteConfig`: Remote config location to HTTP get the JSON based config from.

Others:
- `reportBandwidthTo` (optional): **DEPRECATED** - Use `remoteConfig` instead. Remote HTTP endpoint to send peer bandwidth data
- `interface` (optional): Name of the WireGuard interface created by Gerbil. Default: `wg0`
- `listen` (optional): Port to listen on for HTTP server. Default: `:3004`
- `log-level` (optional): The log level to use (DEBUG, INFO, WARN, ERROR, FATAL). Default: `INFO`
- `mtu` (optional): MTU of the WireGuard interface. Default: `1280`
- `notify` (optional): URL to notify on peer changes
- `sni-port` (optional): Port for the SNI proxy to listen on. Default: `8443`
- `local-proxy` (optional): Address for local proxy when routing local traffic. Default: `localhost`
- `local-proxy-port` (optional): Port for local proxy when routing local traffic. Default: `443`
- `local-overrides` (optional): Comma-separated list of domain names that should always be routed to the local proxy
- `proxy-protocol` (optional): Enable PROXY protocol v1 for preserving client IP addresses when forwarding to downstream proxies. Default: `false`

## Environment Variables

All CLI arguments can also be provided via environment variables:

- `INTERFACE`: Name of the WireGuard interface
- `REMOTE_CONFIG`: URL of the remote config server
- `LISTEN`: Address to listen on for HTTP server
- `GENERATE_AND_SAVE_KEY_TO`: Path to save generated private key
- `REACHABLE_AT`: Endpoint of the HTTP server to tell remote config about
- `LOG_LEVEL`: Log level (DEBUG, INFO, WARN, ERROR, FATAL)
- `MTU`: MTU of the WireGuard interface
- `NOTIFY_URL`: URL to notify on peer changes
- `SNI_PORT`: Port for the SNI proxy to listen on
- `LOCAL_PROXY`: Address for local proxy when routing local traffic
- `LOCAL_PROXY_PORT`: Port for local proxy when routing local traffic
- `LOCAL_OVERRIDES`: Comma-separated list of domain names that should always be routed to the local proxy
- `PROXY_PROTOCOL`: Enable PROXY protocol v1 for preserving client IP addresses (true/false)

Example:

```bash
./gerbil \
--reachableAt=http://gerbil:3004 \
--generateAndSaveKeyTo=/var/config/key \
--remoteConfig=http://pangolin:3001/api/v1/
```

```yaml
services:
  gerbil:
    image: fosrl/gerbil
    container_name: gerbil
    restart: unless-stopped
    command:
      - --reachableAt=http://gerbil:3004
      - --generateAndSaveKeyTo=/var/config/key
      - --remoteConfig=http://pangolin:3001/api/v1/
    volumes:
      - ./config/:/var/config
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    ports:
      - 51820:51820/udp
      - 21820:21820/udp
      - 443:8443/tcp  # SNI proxy port
```

## Build

### Container 

Ensure Docker is installed.

```bash
make
```

### Binary

Make sure to have Go 1.23.1 installed.

```bash
make local
```

## Licensing

Gerbil is dual licensed under the AGPLv3 and the Fossorial Commercial license. For inquiries about commercial licensing, please contact us.

## Contributions

Please see [CONTRIBUTIONS](./CONTRIBUTING.md) in the repository for guidelines and best practices.
