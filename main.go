package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fosrl/gerbil/internal/metrics"
	"github.com/fosrl/gerbil/logger"
	"github.com/fosrl/gerbil/proxy"
	"github.com/fosrl/gerbil/relay"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	interfaceName    string
	listenAddr       string
	mtuInt           int
	lastReadings     = make(map[string]PeerReading)
	mu               sync.Mutex
	wgMu             sync.Mutex // Protects WireGuard operations
	notifyURL        string
	proxyRelay       *relay.UDPProxyServer
	proxySNI         *proxy.SNIProxy
	doTrafficShaping bool
	bandwidthLimit   string
	ifbName          string // IFB device name for ingress traffic shaping
)

type WgConfig struct {
	PrivateKey string `json:"privateKey"`
	ListenPort int    `json:"listenPort"`
	RelayPort  int    `json:"relayPort"`
	IpAddress  string `json:"ipAddress"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
}

type PeerBandwidth struct {
	PublicKey string  `json:"publicKey"`
	BytesIn   float64 `json:"bytesIn"`
	BytesOut  float64 `json:"bytesOut"`
}

type PeerReading struct {
	BytesReceived    int64
	BytesTransmitted int64
	LastChecked      time.Time
}

var (
	wgClient *wgctrl.Client
)

// Add this new type at the top with other type definitions
type ClientEndpoint struct {
	OlmID     string `json:"olmId"`
	NewtID    string `json:"newtId"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"`
}

type HolePunchMessage struct {
	OlmID  string `json:"olmId"`
	NewtID string `json:"newtId"`
}

type ProxyMappingUpdate struct {
	OldDestination relay.PeerDestination `json:"oldDestination"`
	NewDestination relay.PeerDestination `json:"newDestination"`
}

type UpdateDestinationsRequest struct {
	SourceIP     string                  `json:"sourceIp"`
	SourcePort   int                     `json:"sourcePort"`
	Destinations []relay.PeerDestination `json:"destinations"`
}

// httpMetricsMiddleware wraps HTTP handlers with metrics tracking
func httpMetricsMiddleware(endpoint string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Create a response writer wrapper to capture status code
		ww := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the actual handler
		handler(ww, r)

		// Record metrics
		duration := time.Since(startTime).Seconds()
		metrics.RecordHTTPRequest(endpoint, r.Method, fmt.Sprintf("%d", ww.statusCode))
		metrics.RecordHTTPRequestDuration(endpoint, r.Method, duration)
	}
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

func main() {
	go monitorMemory(1024 * 1024 * 512) // trigger if memory usage exceeds 512MB

	var (
		err                  error
		wgconfig             WgConfig
		configFile           string
		remoteConfigURL      string
		generateAndSaveKeyTo string
		reachableAt          string
		logLevel             string
		mtu                  string
		sniProxyPort         int
		localProxyAddr       string
		localProxyPort       int
		localOverridesStr    string
		trustedUpstreamsStr  string
		proxyProtocol        bool

		// Metrics configuration variables (set from env, then overridden by CLI flags)
		metricsEnabled            bool
		metricsBackend            string
		metricsPath               string
		otelMetricsProtocol       string
		otelMetricsEndpoint       string
		otelMetricsInsecure       bool
		otelMetricsExportInterval time.Duration
	)

	interfaceName = os.Getenv("INTERFACE")
	configFile = os.Getenv("CONFIG")
	remoteConfigURL = os.Getenv("REMOTE_CONFIG")
	listenAddr = os.Getenv("LISTEN")
	generateAndSaveKeyTo = os.Getenv("GENERATE_AND_SAVE_KEY_TO")
	reachableAt = os.Getenv("REACHABLE_AT")
	logLevel = os.Getenv("LOG_LEVEL")
	mtu = os.Getenv("MTU")
	notifyURL = os.Getenv("NOTIFY_URL")

	sniProxyPortStr := os.Getenv("SNI_PORT")
	localProxyAddr = os.Getenv("LOCAL_PROXY")
	localProxyPortStr := os.Getenv("LOCAL_PROXY_PORT")
	localOverridesStr = os.Getenv("LOCAL_OVERRIDES")
	trustedUpstreamsStr = os.Getenv("TRUSTED_UPSTREAMS")
	proxyProtocolStr := os.Getenv("PROXY_PROTOCOL")
	doTrafficShapingStr := os.Getenv("DO_TRAFFIC_SHAPING")
	bandwidthLimitStr := os.Getenv("BANDWIDTH_LIMIT")

	// Read metrics env vars (defaults applied by DefaultMetricsConfig; these override defaults).
	metricsEnabled = true // default
	if v := os.Getenv("METRICS_ENABLED"); v != "" {
		metricsEnabled = strings.ToLower(v) == "true"
	}
	metricsBackend = "prometheus" // default
	if v := os.Getenv("METRICS_BACKEND"); v != "" {
		metricsBackend = v
	}
	metricsPath = "/metrics" // default
	if v := os.Getenv("METRICS_PATH"); v != "" {
		metricsPath = v
	}
	otelMetricsProtocol = "grpc" // default
	if v := os.Getenv("OTEL_METRICS_PROTOCOL"); v != "" {
		otelMetricsProtocol = v
	}
	otelMetricsEndpoint = "localhost:4317" // default
	if v := os.Getenv("OTEL_METRICS_ENDPOINT"); v != "" {
		otelMetricsEndpoint = v
	}
	otelMetricsInsecure = true // default
	if v := os.Getenv("OTEL_METRICS_INSECURE"); v != "" {
		otelMetricsInsecure = strings.ToLower(v) == "true"
	}
	otelMetricsExportInterval = 60 * time.Second // default
	if v := os.Getenv("OTEL_METRICS_EXPORT_INTERVAL"); v != "" {
		if d, err2 := time.ParseDuration(v); err2 == nil {
			otelMetricsExportInterval = d
		} else {
			log.Printf("WARN: invalid OTEL_METRICS_EXPORT_INTERVAL=%q: %v", v, err2)
		}
	}

	if interfaceName == "" {
		flag.StringVar(&interfaceName, "interface", "wg0", "Name of the WireGuard interface")
	}
	if configFile == "" {
		flag.StringVar(&configFile, "config", "", "Path to local configuration file")
	}
	if remoteConfigURL == "" {
		flag.StringVar(&remoteConfigURL, "remoteConfig", "", "URL of the Pangolin server")
	}
	if listenAddr == "" {
		flag.StringVar(&listenAddr, "listen", "", "DEPRECATED (overridden by reachableAt): Address to listen on")
	}
	// DEPRECATED AND UNSED: reportBandwidthTo
	// allow reportBandwidthTo to be passed but dont do anything with it just thow it away
	reportBandwidthTo := ""
	flag.StringVar(&reportBandwidthTo, "reportBandwidthTo", "", "DEPRECATED: Use remoteConfig instead")

	if generateAndSaveKeyTo == "" {
		flag.StringVar(&generateAndSaveKeyTo, "generateAndSaveKeyTo", "", "Path to save generated private key")
	}

	if reachableAt == "" {
		flag.StringVar(&reachableAt, "reachableAt", "", "Endpoint of the http server to tell remote config about")
	}

	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if mtu == "" {
		flag.StringVar(&mtu, "mtu", "1280", "MTU of the WireGuard interface")
	}
	if notifyURL == "" {
		flag.StringVar(&notifyURL, "notify", "", "URL to notify on peer changes")
	}

	if sniProxyPortStr != "" {
		if port, err := strconv.Atoi(sniProxyPortStr); err == nil {
			sniProxyPort = port
		}
	}
	if sniProxyPortStr == "" {
		flag.IntVar(&sniProxyPort, "sni-port", 8443, "Port to listen on")
	}

	if localProxyAddr == "" {
		flag.StringVar(&localProxyAddr, "local-proxy", "localhost", "Local proxy address")
	}

	if localProxyPortStr != "" {
		if port, err := strconv.Atoi(localProxyPortStr); err == nil {
			localProxyPort = port
		}
	}
	if localProxyPortStr == "" {
		flag.IntVar(&localProxyPort, "local-proxy-port", 443, "Local proxy port")
	}
	if localOverridesStr != "" {
		flag.StringVar(&localOverridesStr, "local-overrides", "", "Comma-separated list of local overrides for SNI proxy")
	}
	if trustedUpstreamsStr == "" {
		flag.StringVar(&trustedUpstreamsStr, "trusted-upstreams", "", "Comma-separated list of trusted upstream proxy domain names/IPs that can send PROXY protocol")
	}

	if proxyProtocolStr != "" {
		proxyProtocol = strings.ToLower(proxyProtocolStr) == "true"
	}
	if proxyProtocolStr == "" {
		flag.BoolVar(&proxyProtocol, "proxy-protocol", true, "Enable PROXY protocol v1 for preserving client IP")
	}

	if doTrafficShapingStr != "" {
		doTrafficShaping = strings.ToLower(doTrafficShapingStr) == "true"
	}
	if doTrafficShapingStr == "" {
		flag.BoolVar(&doTrafficShaping, "do-traffic-shaping", false, "Whether to set up traffic shaping rules for peers (requires tc command and root privileges)")
	}

	if bandwidthLimitStr != "" {
		bandwidthLimit = bandwidthLimitStr
	}
	if bandwidthLimitStr == "" {
		flag.StringVar(&bandwidthLimit, "bandwidth-limit", "50mbit", "Bandwidth limit per peer for traffic shaping (e.g. 50mbit, 1gbit)")
	}

	// Metrics CLI flags – always registered so that CLI overrides env/defaults.
	flag.BoolVar(&metricsEnabled, "metrics-enabled", metricsEnabled, "Enable metrics collection (default: true)")
	flag.StringVar(&metricsBackend, "metrics-backend", metricsBackend, "Metrics backend: prometheus, otel, or none")
	flag.StringVar(&metricsPath, "metrics-path", metricsPath, "HTTP path for Prometheus /metrics endpoint")
	flag.StringVar(&otelMetricsProtocol, "otel-metrics-protocol", otelMetricsProtocol, "OTLP transport protocol: grpc or http")
	flag.StringVar(&otelMetricsEndpoint, "otel-metrics-endpoint", otelMetricsEndpoint, "OTLP collector endpoint (e.g. localhost:4317)")
	flag.BoolVar(&otelMetricsInsecure, "otel-metrics-insecure", otelMetricsInsecure, "Disable TLS for OTLP connection")
	flag.DurationVar(&otelMetricsExportInterval, "otel-metrics-export-interval", otelMetricsExportInterval, "Interval between OTLP metric pushes")

	flag.Parse()

	// Derive IFB device name from the WireGuard interface name (Linux limit: 15 chars)
	ifbName = "ifb_" + interfaceName
	if len(ifbName) > 15 {
		ifbName = ifbName[:15]
	}

	logger.Init()
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// Initialize metrics with the selected backend.
	// Config precedence: CLI flags > env vars > defaults (already applied above).
	metricsHandler, err := metrics.Initialize(metrics.Config{
		Enabled: metricsEnabled,
		Backend: metricsBackend,
		Prometheus: metrics.PrometheusConfig{
			Path: metricsPath,
		},
		OTel: metrics.OTelConfig{
			Protocol:       otelMetricsProtocol,
			Endpoint:       otelMetricsEndpoint,
			Insecure:       otelMetricsInsecure,
			ExportInterval: otelMetricsExportInterval,
		},
		ServiceName:           "gerbil",
		ServiceVersion:        "1.0.0",
		DeploymentEnvironment: os.Getenv("DEPLOYMENT_ENVIRONMENT"),
	})
	if err != nil {
		logger.Fatal("Failed to initialize metrics: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metrics.Shutdown(shutdownCtx); err != nil {
			logger.Error("Failed to shutdown metrics: %v", err)
		}
	}()

	// Record restart metric
	metrics.RecordRestart()

	// Base context for the application; cancel on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// try to parse as http://host:port and set the listenAddr to the :port from this reachableAt.
	if reachableAt != "" && listenAddr == "" {
		if strings.HasPrefix(reachableAt, "http://") || strings.HasPrefix(reachableAt, "https://") {
			parts := strings.Split(reachableAt, ":")
			if len(parts) == 3 {
				port := parts[2]
				if strings.Contains(port, "/") {
					port = strings.Split(port, "/")[0]
				}
				listenAddr = ":" + port
			}
		}
	} else if listenAddr == "" {
		listenAddr = ":3003"
	}

	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	// are they missing either the config file or the remote config URL?
	if configFile == "" && remoteConfigURL == "" {
		logger.Fatal("You must provide either a config file or a remote config URL")
	}

	// do they have both the config file and the remote config URL?
	if configFile != "" && remoteConfigURL != "" {
		logger.Fatal("You must provide either a config file or a remote config URL, not both")
	}

	// clean up the reomte config URL for backwards compatibility
	remoteConfigURL = strings.TrimSuffix(remoteConfigURL, "/gerbil/get-config")
	remoteConfigURL = strings.TrimSuffix(remoteConfigURL, "/")

	var key wgtypes.Key
	// if generateAndSaveKeyTo is provided, generate a private key and save it to the file. if the file already exists, load the key from the file
	if generateAndSaveKeyTo != "" {
		if _, err := os.Stat(generateAndSaveKeyTo); os.IsNotExist(err) {
			// generate a new private key
			key, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				logger.Fatal("Failed to generate private key: %v", err)
			}
			// save the key to the file
			err = os.WriteFile(generateAndSaveKeyTo, []byte(key.String()), 0644)
			if err != nil {
				logger.Fatal("Failed to save private key: %v", err)
			}
		} else {
			keyData, err := os.ReadFile(generateAndSaveKeyTo)
			if err != nil {
				logger.Fatal("Failed to read private key: %v", err)
			}
			key, err = wgtypes.ParseKey(string(keyData))
			if err != nil {
				logger.Fatal("Failed to parse private key: %v", err)
			}
		}
	} else {
		// if no generateAndSaveKeyTo is provided, ensure that the private key is provided
		if wgconfig.PrivateKey == "" {
			// generate a new one
			key, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				logger.Fatal("Failed to generate private key: %v", err)
			}
		}
	}

	// Load configuration based on provided argument
	if configFile != "" {
		wgconfig, err = loadConfig(configFile)
		if err != nil {
			logger.Fatal("Failed to load configuration: %v", err)
		}
		if wgconfig.PrivateKey == "" {
			wgconfig.PrivateKey = key.String()
		}
	} else {
		// loop until we get the config
		for wgconfig.PrivateKey == "" {
			logger.Info("Fetching remote config from %s", remoteConfigURL+"/gerbil/get-config")
			wgconfig, err = loadRemoteConfig(remoteConfigURL+"/gerbil/get-config", key, reachableAt)
			if err != nil {
				logger.Error("Failed to load configuration: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			wgconfig.PrivateKey = key.String()
		}
	}

	wgClient, err = wgctrl.New()
	if err != nil {
		logger.Fatal("Failed to create WireGuard client: %v", err)
	}
	defer wgClient.Close()

	// Ensure the WireGuard interface exists and is configured
	if err := ensureWireguardInterface(wgconfig); err != nil {
		logger.Fatal("Failed to ensure WireGuard interface: %v", err)
	}

	// Set up IFB device for bidirectional ingress/egress traffic shaping if enabled
	if doTrafficShaping {
		if err := ensureIFBDevice(); err != nil {
			logger.Fatal("Failed to ensure IFB device for traffic shaping: %v", err)
		}
	}

	// Ensure the WireGuard peers exist
	ensureWireguardPeers(wgconfig.Peers)

	// Child error group derived from base context
	group, groupCtx := errgroup.WithContext(ctx)

	// Periodic bandwidth reporting
	group.Go(func() error {
		return periodicBandwidthCheck(groupCtx, remoteConfigURL+"/gerbil/receive-bandwidth")
	})

	// Start the UDP proxy server
	relayPort := wgconfig.RelayPort
	if relayPort == 0 {
		relayPort = 21820 // in case there is no relay port set, use 21820
	}
	proxyRelay = relay.NewUDPProxyServer(groupCtx, fmt.Sprintf(":%d", relayPort), remoteConfigURL, key, reachableAt)
	err = proxyRelay.Start()
	if err != nil {
		logger.Fatal("Failed to start UDP proxy server: %v", err)
	}
	defer proxyRelay.Stop()

	// TODO: WE SHOULD PULL THIS OUT OF THE CONFIG OR SOMETHING
	// 		 SO YOU DON'T NEED TO SET THIS SEPARATELY
	// Parse local overrides
	var localOverrides []string
	if localOverridesStr != "" {
		localOverrides = strings.Split(localOverridesStr, ",")
		for i, domain := range localOverrides {
			localOverrides[i] = strings.TrimSpace(domain)
		}
		logger.Info("Local overrides configured: %v", localOverrides)
	}

	var trustedUpstreams []string
	if trustedUpstreamsStr != "" {
		trustedUpstreams = strings.Split(trustedUpstreamsStr, ",")
		for i, upstream := range trustedUpstreams {
			trustedUpstreams[i] = strings.TrimSpace(upstream)
		}
		logger.Info("Trusted upstreams configured: %v", trustedUpstreams)
	}

	proxySNI, err = proxy.NewSNIProxy(sniProxyPort, remoteConfigURL, key.PublicKey().String(), localProxyAddr, localProxyPort, localOverrides, proxyProtocol, trustedUpstreams)
	if err != nil {
		logger.Fatal("Failed to create proxy: %v", err)
	}

	if err := proxySNI.Start(); err != nil {
		logger.Fatal("Failed to start proxy: %v", err)
	}

	// Set up HTTP server with metrics middleware
	http.HandleFunc("/peer", httpMetricsMiddleware("peer", handlePeer))
	http.HandleFunc("/update-proxy-mapping", httpMetricsMiddleware("update_proxy_mapping", handleUpdateProxyMapping))
	http.HandleFunc("/update-destinations", httpMetricsMiddleware("update_destinations", handleUpdateDestinations))
	http.HandleFunc("/update-local-snis", httpMetricsMiddleware("update_local_snis", handleUpdateLocalSNIs))
	http.HandleFunc("/healthz", httpMetricsMiddleware("healthz", handleHealthz))

	// Register metrics endpoint only for Prometheus backend.
	// OTel backend pushes to a collector; no /metrics endpoint needed.
	if metricsHandler != nil {
		http.Handle(metricsPath, metricsHandler)
		logger.Info("Metrics endpoint enabled at %s", metricsPath)
	}

	logger.Info("Starting HTTP server on %s", listenAddr)

	// HTTP server with graceful shutdown on context cancel
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           nil,
		ReadHeaderTimeout: 3 * time.Second,
	}
	group.Go(func() error {
		// http.ErrServerClosed is returned on graceful shutdown; not an error for us
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		// Stop background components as the context is canceled
		if proxySNI != nil {
			_ = proxySNI.Stop()
		}
		if proxyRelay != nil {
			proxyRelay.Stop()
		}
		return nil
	})

	// Wait for all goroutines to finish
	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("Service exited with error: %v", err)
	} else if errors.Is(err, context.Canceled) {
		logger.Info("Context cancelled, shutting down")
	}
}

func loadRemoteConfig(url string, key wgtypes.Key, reachableAt string) (WgConfig, error) {
	var body *bytes.Buffer
	if reachableAt == "" {
		body = bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": %q}`, key.PublicKey().String())))
	} else {
		body = bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": %q, "reachableAt": %q}`, key.PublicKey().String(), reachableAt)))
	}
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		// print the error
		logger.Error("Error fetching remote config %s: %v", url, err)
		// Record remote config fetch error
		metrics.RecordRemoteConfigFetch("error")
		return WgConfig{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		metrics.RecordRemoteConfigFetch("error")
		return WgConfig{}, err
	}

	var config WgConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		metrics.RecordRemoteConfigFetch("error")
		return config, err
	}

	// Record successful remote config fetch
	metrics.RecordRemoteConfigFetch("success")
	return config, err
}

func loadConfig(filename string) (WgConfig, error) {
	// Open the JSON file
	file, err := os.Open(filename)
	if err != nil {
		logger.Error("Error opening file %s: %v", filename, err)
		return WgConfig{}, err
	}
	defer file.Close()

	// Read the file contents
	byteValue, err := io.ReadAll(file)
	if err != nil {
		logger.Error("Error reading file %s: %v", filename, err)
		return WgConfig{}, err
	}

	// Create a variable of the appropriate type to hold the unmarshaled data
	var wgconfig WgConfig

	// Unmarshal the JSON data into the struct
	err = json.Unmarshal(byteValue, &wgconfig)
	if err != nil {
		logger.Error("Error unmarshaling JSON data: %v", err)
		return WgConfig{}, err
	}

	return wgconfig, nil
}

func ensureWireguardInterface(wgconfig WgConfig) error {
	// Check if the WireGuard interface exists
	_, err := netlink.LinkByName(interfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Interface doesn't exist, so create it
			err = createWireGuardInterface()
			if err != nil {
				logger.Fatal("Failed to create WireGuard interface: %v", err)
			}
			logger.Info("Created WireGuard interface %s\n", interfaceName)
		} else {
			logger.Fatal("Error checking for WireGuard interface: %v", err)
		}
	} else {
		logger.Info("WireGuard interface %s already exists\n", interfaceName)
		return nil
	}

	// Assign IP address to the interface
	err = assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		logger.Fatal("Failed to assign IP address: %v", err)
	}
	logger.Info("Assigned IP address %s to interface %s\n", wgconfig.IpAddress, interfaceName)

	// Check if the interface already exists
	_, err = wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Parse the private key
	key, err := wgtypes.ParseKey(wgconfig.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create a new WireGuard configuration
	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: new(int),
	}
	*config.ListenPort = wgconfig.ListenPort

	// Create and configure the WireGuard interface
	err = wgClient.ConfigureDevice(interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// bring up the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	if err := netlink.LinkSetMTU(link, mtuInt); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	if err := ensureMSSClamping(); err != nil {
		logger.Warn("Failed to ensure MSS clamping: %v", err)
	}

	if err := ensureWireguardFirewall(); err != nil {
		logger.Warn("Failed to ensure WireGuard firewall rules: %v", err)
	}

	logger.Info("WireGuard interface %s created and configured", interfaceName)

	// Record interface state metric
	hostname, _ := os.Hostname()
	metrics.RecordInterfaceUp(interfaceName, hostname, true)

	return nil
}

func createWireGuardInterface() error {
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
		LinkType:  "wireguard",
	}
	return netlink.LinkAdd(wgLink)
}

func assignIPAddress(ipAddress string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	addr, err := netlink.ParseAddr(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address: %v", err)
	}

	return netlink.AddrAdd(link, addr)
}

func ensureWireguardPeers(peers []Peer) error {
	wgMu.Lock()
	defer wgMu.Unlock()

	// get the current peers
	device, err := wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %v", err)
	}

	// get the peer public keys
	var currentPeers []string
	for _, peer := range device.Peers {
		currentPeers = append(currentPeers, peer.PublicKey.String())
	}

	// remove any peers that are not in the config
	for _, peer := range currentPeers {
		found := false
		for _, configPeer := range peers {
			if peer == configPeer.PublicKey {
				found = true
				break
			}
		}
		if !found {
			// Note: We need to call the internal removal logic without re-acquiring the lock
			if err := removePeerInternal(peer); err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	}

	// add any peers that are in the config but not in the current peers
	for _, configPeer := range peers {
		found := false
		for _, peer := range currentPeers {
			if configPeer.PublicKey == peer {
				found = true
				break
			}
		}
		if !found {
			// Note: We need to call the internal addition logic without re-acquiring the lock
			if err := addPeerInternal(configPeer); err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	}

	return nil
}

func ensureMSSClamping() error {
	// Calculate MSS value (MTU - 40 for IPv4 header (20) and TCP header (20))
	mssValue := mtuInt - 40

	// Rules to be managed - just the chains, we'll construct the full command separately
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	// First, try to delete any existing rules
	for _, chain := range chains {
		deleteCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-D", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Attempting to delete existing MSS clamping rule for chain %s", chain)

		// Try deletion multiple times to handle multiple existing rules
		for i := 0; i < 3; i++ {
			out, err := deleteCmd.CombinedOutput()
			if err != nil {
				// Convert exit status 1 to string for better logging
				if exitErr, ok := err.(*exec.ExitError); ok {
					logger.Debug("Deletion stopped for chain %s: %v (output: %s)",
						chain, exitErr.String(), string(out))
				}
				break // No more rules to delete
			}
			logger.Info("Deleted MSS clamping rule for chain %s (attempt %d)", chain, i+1)
		}
	}

	// Then add the new rules
	var errors []error
	for _, chain := range chains {
		addCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-A", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Adding MSS clamping rule for chain %s", chain)

		if out, err := addCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Failed to add MSS clamping rule for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error("%s", errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		// Verify the rule was added
		checkCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-C", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		if out, err := checkCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Rule verification failed for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error("%s", errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		logger.Info("Successfully added and verified MSS clamping rule for chain %s", chain)
	}

	// If we encountered any errors, return them combined
	if len(errors) > 0 {
		var errMsgs []string
		for _, err := range errors {
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("MSS clamping setup encountered errors:\n%s",
			strings.Join(errMsgs, "\n"))
	}

	return nil
}

func ensureWireguardFirewall() error {
	// Rules to enforce:
	// 1. Allow established/related connections (responses to our outbound traffic)
	// 2. Allow ICMP ping packets
	// 3. Drop all other inbound traffic from peers

	// Define the rules we want to ensure exist
	rules := [][]string{
		// Allow established and related connections (responses to outbound traffic)
		{
			"-A", "INPUT",
			"-i", interfaceName,
			"-m", "conntrack",
			"--ctstate", "ESTABLISHED,RELATED",
			"-j", "ACCEPT",
		},
		// Allow ICMP ping requests
		{
			"-A", "INPUT",
			"-i", interfaceName,
			"-p", "icmp",
			"--icmp-type", "8",
			"-j", "ACCEPT",
		},
		// Drop all other inbound traffic from WireGuard interface
		{
			"-A", "INPUT",
			"-i", interfaceName,
			"-j", "DROP",
		},
	}

	// First, try to delete any existing rules for this interface
	for _, rule := range rules {
		deleteArgs := make([]string, len(rule))
		copy(deleteArgs, rule)
		// Change -A to -D for deletion
		for i, arg := range deleteArgs {
			if arg == "-A" {
				deleteArgs[i] = "-D"
				break
			}
		}

		deleteCmd := exec.Command("/usr/sbin/iptables", deleteArgs...)
		logger.Debug("Attempting to delete existing firewall rule: %v", deleteArgs)

		// Try deletion multiple times to handle multiple existing rules
		for i := 0; i < 5; i++ {
			out, err := deleteCmd.CombinedOutput()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					logger.Debug("Deletion stopped: %v (output: %s)", exitErr.String(), string(out))
				}
				break // No more rules to delete
			}
			logger.Info("Deleted existing firewall rule (attempt %d)", i+1)
		}
	}

	// Now add the rules
	var errors []error
	for i, rule := range rules {
		addCmd := exec.Command("/usr/sbin/iptables", rule...)
		logger.Info("Adding WireGuard firewall rule %d: %v", i+1, rule)

		if out, err := addCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Failed to add firewall rule %d: %v (output: %s)", i+1, err, string(out))
			logger.Error("%s", errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		// Verify the rule was added by checking
		checkArgs := make([]string, len(rule))
		copy(checkArgs, rule)
		// Change -A to -C for check
		for j, arg := range checkArgs {
			if arg == "-A" {
				checkArgs[j] = "-C"
				break
			}
		}

		checkCmd := exec.Command("/usr/sbin/iptables", checkArgs...)
		if out, err := checkCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Rule verification failed for rule %d: %v (output: %s)", i+1, err, string(out))
			logger.Error("%s", errMsg)
			errors = append(errors, fmt.Errorf("%s", errMsg))
			continue
		}

		logger.Info("Successfully added and verified WireGuard firewall rule %d", i+1)
	}

	if len(errors) > 0 {
		var errMsgs []string
		for _, err := range errors {
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("WireGuard firewall setup encountered errors:\n%s", strings.Join(errMsgs, "\n"))
	}

	logger.Info("WireGuard firewall rules successfully configured for interface %s", interfaceName)
	return nil
}

func handlePeer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleAddPeer(w, r)
	case http.MethodDelete:
		handleRemovePeer(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func handleAddPeer(w http.ResponseWriter, r *http.Request) {
	var peer Peer
	if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		// Record peer add error
		metrics.RecordPeerOperation("add", "error")
		return
	}

	err := addPeer(peer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// Record peer add error
		metrics.RecordPeerOperation("add", "error")
		return
	}

	// Record peer add success
	metrics.RecordPeerOperation("add", "success")

	// Notify if notifyURL is set
	go notifyPeerChange("add", peer.PublicKey)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer added successfully"})
}

func addPeer(peer Peer) error {
	wgMu.Lock()
	defer wgMu.Unlock()
	return addPeerInternal(peer)
}

func addPeerInternal(peer Peer) error {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	logger.Debug("Adding peer %s with AllowedIPs: %v", peer.PublicKey, peer.AllowedIPs)

	// parse allowed IPs into array of net.IPNet
	var allowedIPs []net.IPNet
	var wgIPs []string
	for _, ipStr := range peer.AllowedIPs {
		logger.Debug("Parsing AllowedIP: %s", ipStr)
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			logger.Warn("Failed to parse allowed IP '%s' for peer %s: %v", ipStr, peer.PublicKey, err)
			return fmt.Errorf("failed to parse allowed IP: %v", err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
		// Extract the IP address from the CIDR for relay cleanup
		extractedIP := ipNet.IP.String()
		wgIPs = append(wgIPs, extractedIP)
		logger.Debug("Extracted IP %s from AllowedIP %s", extractedIP, ipStr)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	// Setup bandwidth limiting for each peer IP
	if doTrafficShaping {
		logger.Debug("doTrafficShaping is true, setting up bandwidth limits for %d IPs", len(wgIPs))
		for _, wgIP := range wgIPs {
			if err := setupPeerBandwidthLimit(wgIP); err != nil {
				logger.Warn("Failed to setup bandwidth limit for peer IP %s: %v", wgIP, err)
			}
		}
	} else {
		logger.Debug("doTrafficShaping is false, skipping bandwidth limit setup")
	}

	// Clear relay connections for the peer's WireGuard IPs
	if proxyRelay != nil {
		for _, wgIP := range wgIPs {
			proxyRelay.OnPeerAdded(wgIP)
		}
	}

	logger.Info("Peer %s added successfully", peer.PublicKey)

	// Record metrics
	metrics.RecordPeersTotal(interfaceName, 1)
	metrics.RecordAllowedIPsCount(interfaceName, peer.PublicKey, int64(len(peer.AllowedIPs)))

	return nil
}

func handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	publicKey := r.URL.Query().Get("public_key")
	if publicKey == "" {
		http.Error(w, "Missing public_key query parameter", http.StatusBadRequest)
		// Record peer remove error
		metrics.RecordPeerOperation("remove", "error")
		return
	}

	err := removePeer(publicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		// Record peer remove error
		metrics.RecordPeerOperation("remove", "error")
		return
	}

	// Record peer remove success
	metrics.RecordPeerOperation("remove", "success")

	// Notify if notifyURL is set
	go notifyPeerChange("remove", publicKey)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Peer removed successfully"})
}

func removePeer(publicKey string) error {
	wgMu.Lock()
	defer wgMu.Unlock()
	return removePeerInternal(publicKey)
}

func removePeerInternal(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Get current peer info before removing to clear relay connections and bandwidth limits
	var wgIPs []string
	device, err := wgClient.Device(interfaceName)
	if err == nil {
		for _, peer := range device.Peers {
			if peer.PublicKey.String() == publicKey {
				// Extract WireGuard IPs from this peer's allowed IPs
				for _, allowedIP := range peer.AllowedIPs {
					wgIPs = append(wgIPs, allowedIP.IP.String())
				}
				break
			}
		}
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %v", err)
	}

	// Remove bandwidth limits for each peer IP
	if doTrafficShaping {
		for _, wgIP := range wgIPs {
			if err := removePeerBandwidthLimit(wgIP); err != nil {
				logger.Warn("Failed to remove bandwidth limit for peer IP %s: %v", wgIP, err)
			}
		}
	}

	// Clear relay connections for the peer's WireGuard IPs
	if proxyRelay != nil {
		for _, wgIP := range wgIPs {
			proxyRelay.OnPeerRemoved(wgIP)
		}
	}

	logger.Info("Peer %s removed successfully", publicKey)

	// Record metrics
	metrics.RecordPeersTotal(interfaceName, -1)
	metrics.RecordAllowedIPsCount(interfaceName, publicKey, -int64(len(wgIPs)))

	return nil
}

func handleUpdateProxyMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var update ProxyMappingUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		logger.Error("Failed to decode request body: %v", err)
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the update request
	if update.OldDestination.DestinationIP == "" || update.NewDestination.DestinationIP == "" {
		logger.Error("Both old and new destination IP addresses are required")
		http.Error(w, "Both old and new destination IP addresses are required", http.StatusBadRequest)
		return
	}

	if update.OldDestination.DestinationPort <= 0 || update.NewDestination.DestinationPort <= 0 {
		logger.Error("Both old and new destination ports must be positive integers")
		http.Error(w, "Both old and new destination ports must be positive integers", http.StatusBadRequest)
		return
	}

	// Update the proxy mappings in the relay server
	if proxyRelay == nil {
		logger.Error("Proxy server is not available")
		http.Error(w, "Proxy server is not available", http.StatusInternalServerError)
		// Record error
		metrics.RecordProxyMappingUpdateRequest("error")
		return
	}

	updatedCount := proxyRelay.UpdateDestinationInMappings(update.OldDestination, update.NewDestination)

	logger.Info("Updated %d proxy mappings: %s:%d -> %s:%d",
		updatedCount,
		update.OldDestination.DestinationIP, update.OldDestination.DestinationPort,
		update.NewDestination.DestinationIP, update.NewDestination.DestinationPort)

	// Record success
	metrics.RecordProxyMappingUpdateRequest("success")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "Proxy mappings updated successfully",
		"updatedCount":   updatedCount,
		"oldDestination": update.OldDestination,
		"newDestination": update.NewDestination,
	})
}

func handleUpdateDestinations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request UpdateDestinationsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		logger.Error("Failed to decode request body: %v", err)
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the request
	if request.SourceIP == "" {
		logger.Error("Source IP address is required")
		http.Error(w, "Source IP address is required", http.StatusBadRequest)
		return
	}

	if request.SourcePort <= 0 {
		logger.Error("Source port must be a positive integer")
		http.Error(w, "Source port must be a positive integer", http.StatusBadRequest)
		return
	}

	if len(request.Destinations) == 0 {
		logger.Error("At least one destination is required")
		http.Error(w, "At least one destination is required", http.StatusBadRequest)
		return
	}

	// Validate each destination
	for i, dest := range request.Destinations {
		if dest.DestinationIP == "" {
			logger.Error("Destination IP is required for destination %d", i)
			http.Error(w, fmt.Sprintf("Destination IP is required for destination %d", i), http.StatusBadRequest)
			return
		}
		if dest.DestinationPort <= 0 {
			logger.Error("Destination port must be a positive integer for destination %d", i)
			http.Error(w, fmt.Sprintf("Destination port must be a positive integer for destination %d", i), http.StatusBadRequest)
			return
		}
	}

	// Update the proxy mappings in the relay server
	if proxyRelay == nil {
		logger.Error("Proxy server is not available")
		http.Error(w, "Proxy server is not available", http.StatusInternalServerError)
		// Record error
		metrics.RecordDestinationsUpdateRequest("error")
		return
	}

	proxyRelay.UpdateProxyMapping(request.SourceIP, request.SourcePort, request.Destinations)

	logger.Info("Updated proxy mapping for %s:%d with %d destinations",
		request.SourceIP, request.SourcePort, len(request.Destinations))

	// Record success
	metrics.RecordDestinationsUpdateRequest("success")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "Destinations updated successfully",
		"sourceIP":         request.SourceIP,
		"sourcePort":       request.SourcePort,
		"destinationCount": len(request.Destinations),
		"destinations":     request.Destinations,
	})
}

// UpdateLocalSNIsRequest represents the JSON payload for updating local SNIs
type UpdateLocalSNIsRequest struct {
	FullDomains []string `json:"fullDomains"`
}

func handleUpdateLocalSNIs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logger.Error("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UpdateLocalSNIsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	proxySNI.UpdateLocalSNIs(req.FullDomains)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "Local SNIs updated successfully",
	})
}

func periodicBandwidthCheck(ctx context.Context, endpoint string) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := reportPeerBandwidth(endpoint); err != nil {
				logger.Info("Failed to report peer bandwidth: %v", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func calculatePeerBandwidth() ([]PeerBandwidth, error) {
	wgMu.Lock()
	device, err := wgClient.Device(interfaceName)
	wgMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	var peerBandwidths []PeerBandwidth
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	// Track the set of peers currently present on the device to prune stale readings efficiently
	currentPeerKeys := make(map[string]struct{}, len(device.Peers))

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		currentPeerKeys[publicKey] = struct{}{}

		currentReading := PeerReading{
			BytesReceived:    peer.ReceiveBytes,
			BytesTransmitted: peer.TransmitBytes,
			LastChecked:      now,
		}

		var bytesInDiff, bytesOutDiff float64
		lastReading, exists := lastReadings[publicKey]

		if exists {
			timeDiff := currentReading.LastChecked.Sub(lastReading.LastChecked).Seconds()
			if timeDiff > 0 {
				// Calculate bytes transferred since last reading
				bytesInDiff = float64(currentReading.BytesReceived - lastReading.BytesReceived)
				bytesOutDiff = float64(currentReading.BytesTransmitted - lastReading.BytesTransmitted)

				// Handle counter wraparound (if the counter resets or overflows)
				if bytesInDiff < 0 {
					bytesInDiff = float64(currentReading.BytesReceived)
				}
				if bytesOutDiff < 0 {
					bytesOutDiff = float64(currentReading.BytesTransmitted)
				}

				// Convert to MB
				bytesInMB := bytesInDiff / (1024 * 1024)
				bytesOutMB := bytesOutDiff / (1024 * 1024)

				// Record metrics (in bytes)
				if bytesInDiff > 0 {
					metrics.RecordBytesReceived(interfaceName, publicKey, int64(bytesInDiff))
				}
				if bytesOutDiff > 0 {
					metrics.RecordBytesTransmitted(interfaceName, publicKey, int64(bytesOutDiff))
				}

				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   bytesInMB,
					BytesOut:  bytesOutMB,
				})
			} else {
				// If readings are too close together or time hasn't passed, report 0
				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   0,
					BytesOut:  0,
				})
			}
		} else {
			// For first reading of a peer, report 0 to establish baseline
			peerBandwidths = append(peerBandwidths, PeerBandwidth{
				PublicKey: publicKey,
				BytesIn:   0,
				BytesOut:  0,
			})
		}

		// Update the last reading
		lastReadings[publicKey] = currentReading
	}

	// Clean up old peers
	for publicKey := range lastReadings {
		if _, exists := currentPeerKeys[publicKey]; !exists {
			delete(lastReadings, publicKey)
		}
	}

	return peerBandwidths, nil
}

func reportPeerBandwidth(apiURL string) error {
	bandwidths, err := calculatePeerBandwidth()
	if err != nil {
		// Record bandwidth report error
		metrics.RecordBandwidthReport("error")
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	jsonData, err := json.Marshal(bandwidths)
	if err != nil {
		metrics.RecordBandwidthReport("error")
		return fmt.Errorf("failed to marshal bandwidth data: %v", err)
	}

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		metrics.RecordBandwidthReport("error")
		return fmt.Errorf("failed to send bandwidth data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		metrics.RecordBandwidthReport("error")
		return fmt.Errorf("API returned non-OK status: %s", resp.Status)
	}

	// Record successful bandwidth report
	metrics.RecordBandwidthReport("success")
	return nil
}

// notifyPeerChange sends a POST request to notifyURL with the action and public key.
func notifyPeerChange(action, publicKey string) {
	if notifyURL == "" {
		return
	}
	payload := map[string]string{
		"action":    action,
		"publicKey": publicKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("Failed to marshal notify payload: %v", err)
		return
	}
	resp, err := http.Post(notifyURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		logger.Warn("Failed to notify peer change: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Warn("Notify server returned non-OK: %s", resp.Status)
	}
}

func monitorMemory(limit uint64) {
	var m runtime.MemStats
	for {
		runtime.ReadMemStats(&m)
		if m.Alloc > limit {
			// Determine severity based on how much over the limit
			severity := "warning"
			if m.Alloc > limit*2 {
				severity = "critical"
			}

			fmt.Printf("Memory spike detected (%d bytes). Dumping profile...\n", m.Alloc)

			// Record memory spike metric
			metrics.RecordMemorySpike(severity)

			f, err := os.Create(fmt.Sprintf("/var/config/heap/heap-spike-%d.pprof", time.Now().Unix()))
			if err != nil {
				log.Println("could not create profile:", err)
			} else {
				pprof.WriteHeapProfile(f)
				f.Close()
				// Record heap profile written metric
				metrics.RecordHeapProfileWritten()
			}

			// Wait a while before checking again to avoid spamming profiles
			time.Sleep(5 * time.Minute)
		}
		time.Sleep(5 * time.Second)
	}
}

// ensureIFBDevice creates and configures the IFB (Intermediate Functional Block) device used to
// shape ingress traffic on the WireGuard interface. Linux TC qdiscs only control egress by default;
// the IFB trick redirects all ingress packets to a virtual device so HTB shaping can be applied
// there, and the packets are transparently re-injected into the kernel network stack afterwards.
// This is completely invisible to sockets/applications (including a reverse proxy on the host).
func ensureIFBDevice() error {
	// Check if the ifb kernel module is loaded (works inside containers too)
	if _, err := os.Stat("/sys/module/ifb"); os.IsNotExist(err) {
		logger.Warn("IFB module not loaded, skipping IFB setup and ingress traffic shaping")
		return nil
	}

	// Create the IFB device if it does not already exist
	_, err := netlink.LinkByName(ifbName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			cmd := exec.Command("ip", "link", "add", ifbName, "type", "ifb")
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to create IFB device %s: %v, output: %s", ifbName, err, string(out))
			}
			logger.Info("Created IFB device %s", ifbName)
		} else {
			return fmt.Errorf("failed to look up IFB device %s: %v", ifbName, err)
		}
	} else {
		logger.Info("IFB device %s already exists", ifbName)
	}

	// Bring the IFB device up
	cmd := exec.Command("ip", "link", "set", "dev", ifbName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up IFB device %s: %v, output: %s", ifbName, err, string(out))
	}

	// Attach an ingress qdisc to the WireGuard interface if one is not already present
	cmd = exec.Command("tc", "qdisc", "show", "dev", interfaceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to query qdiscs on %s: %v", interfaceName, err)
	}
	if !strings.Contains(string(out), "ingress") {
		cmd = exec.Command("tc", "qdisc", "add", "dev", interfaceName, "handle", "ffff:", "ingress")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add ingress qdisc to %s: %v, output: %s", interfaceName, err, string(out))
		}
		logger.Info("Added ingress qdisc to %s", interfaceName)
	}

	// Add a catch-all filter that redirects every ingress packet from wg0 to the IFB device.
	// Per-peer rate limiting then happens on ifb0's egress HTB qdisc (handle 2:).
	cmd = exec.Command("tc", "filter", "show", "dev", interfaceName, "parent", "ffff:")
	out, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), ifbName) {
		cmd = exec.Command("tc", "filter", "add", "dev", interfaceName,
			"parent", "ffff:", "protocol", "ip",
			"u32", "match", "u32", "0", "0",
			"action", "mirred", "egress", "redirect", "dev", ifbName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add ingress redirect filter on %s: %v, output: %s", interfaceName, err, string(out))
		}
		logger.Info("Added ingress redirect filter: %s -> %s", interfaceName, ifbName)
	}

	// Ensure an HTB root qdisc exists on the IFB device (handle 2:) for per-peer shaping
	cmd = exec.Command("tc", "qdisc", "show", "dev", ifbName)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to query qdiscs on %s: %v", ifbName, err)
	}
	if !strings.Contains(string(out), "htb") {
		cmd = exec.Command("tc", "qdisc", "add", "dev", ifbName, "root", "handle", "2:", "htb", "default", "9999")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add HTB qdisc to %s: %v, output: %s", ifbName, err, string(out))
		}
		logger.Info("Added HTB root qdisc (handle 2:) to IFB device %s", ifbName)
	}

	logger.Info("IFB device %s ready for ingress traffic shaping", ifbName)
	return nil
}

// setupPeerBandwidthLimit sets up TC (Traffic Control) to limit bandwidth for a specific peer IP
// Bandwidth limit is configurable via the --bandwidth-limit flag or BANDWIDTH_LIMIT env var (default: 50mbit)
func setupPeerBandwidthLimit(peerIP string) error {
	logger.Debug("setupPeerBandwidthLimit called for peer IP: %s", peerIP)

	// Parse the IP to get just the IP address (strip any CIDR notation if present)
	ip := peerIP
	if strings.Contains(peerIP, "/") {
		parsedIP, _, err := net.ParseCIDR(peerIP)
		if err != nil {
			return fmt.Errorf("failed to parse peer IP: %v", err)
		}
		ip = parsedIP.String()
	}

	// First, ensure we have a root qdisc on the interface (HTB - Hierarchical Token Bucket)
	// Check if qdisc already exists
	cmd := exec.Command("tc", "qdisc", "show", "dev", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check qdisc: %v, output: %s", err, string(output))
	}

	// If no HTB qdisc exists, create one
	if !strings.Contains(string(output), "htb") {
		cmd = exec.Command("tc", "qdisc", "add", "dev", interfaceName, "root", "handle", "1:", "htb", "default", "9999")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add root qdisc: %v, output: %s", err, string(output))
		}
		logger.Info("Created HTB root qdisc on %s", interfaceName)
	}

	// Generate a unique class ID based on the IP address
	// We'll use the last octet of the IP as part of the class ID
	ipParts := strings.Split(ip, ".")
	if len(ipParts) != 4 {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	lastOctet := ipParts[3]
	classID := fmt.Sprintf("1:%s", lastOctet)
	logger.Debug("Generated class ID %s for peer IP %s", classID, ip)

	// Create a class for this peer with bandwidth limit
	cmd = exec.Command("tc", "class", "add", "dev", interfaceName, "parent", "1:", "classid", classID,
		"htb", "rate", bandwidthLimit, "ceil", bandwidthLimit)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Debug("tc class add failed for %s: %v, output: %s", ip, err, string(output))
		// If class already exists, try to replace it
		if strings.Contains(string(output), "File exists") {
			cmd = exec.Command("tc", "class", "replace", "dev", interfaceName, "parent", "1:", "classid", classID,
				"htb", "rate", bandwidthLimit, "ceil", bandwidthLimit)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to replace class: %v, output: %s", err, string(output))
			}
			logger.Debug("Successfully replaced existing class %s for peer IP %s", classID, ip)
		} else {
			return fmt.Errorf("failed to add class: %v, output: %s", err, string(output))
		}
	} else {
		logger.Debug("Successfully added new class %s for peer IP %s", classID, ip)
	}

	// Add a filter to match traffic to this peer IP on wg0 egress (peer's download)
	cmd = exec.Command("tc", "filter", "add", "dev", interfaceName, "protocol", "ip", "parent", "1:",
		"prio", "1", "u32", "match", "ip", "dst", ip, "flowid", classID)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("Failed to add egress filter for peer IP %s: %v, output: %s", ip, err, string(output))
	}

	// Set up ingress shaping on the IFB device (peer's upload / ingress on wg0).
	// All wg0 ingress is redirected to ifb0 by ensureIFBDevice; we add a per-peer
	// class + src filter here so each peer gets its own independent rate limit.
	ifbClassID := fmt.Sprintf("2:%s", lastOctet)

	// Check if the ifb kernel module is loaded (works inside containers too)
	if _, err := os.Stat("/sys/module/ifb"); os.IsNotExist(err) {
		logger.Warn("IFB module not loaded, skipping IFB setup and ingress traffic shaping.")
		logger.Info("Setup bandwidth limit of %s for peer IP %s (egress class %s, ingress class %s)", bandwidthLimit, ip, classID, ifbClassID)
		return nil
	}

	cmd = exec.Command("tc", "class", "add", "dev", ifbName, "parent", "2:", "classid", ifbClassID,
		"htb", "rate", bandwidthLimit, "ceil", bandwidthLimit)
	if output, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "File exists") {
			cmd = exec.Command("tc", "class", "replace", "dev", ifbName, "parent", "2:", "classid", ifbClassID,
				"htb", "rate", bandwidthLimit, "ceil", bandwidthLimit)
			if output, err := cmd.CombinedOutput(); err != nil {
				logger.Warn("Failed to replace IFB class for peer IP %s: %v, output: %s", ip, err, string(output))
			} else {
				logger.Debug("Replaced existing IFB class %s for peer IP %s", ifbClassID, ip)
			}
		} else {
			logger.Warn("Failed to add IFB class for peer IP %s: %v, output: %s", ip, err, string(output))
		}
	} else {
		logger.Debug("Added IFB class %s for peer IP %s", ifbClassID, ip)
	}

	cmd = exec.Command("tc", "filter", "add", "dev", ifbName, "protocol", "ip", "parent", "2:",
		"prio", "1", "u32", "match", "ip", "src", ip, "flowid", ifbClassID)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("Failed to add IFB ingress filter for peer IP %s: %v, output: %s", ip, err, string(output))
	}

	logger.Info("Setup bandwidth limit of %s for peer IP %s (egress class %s, ingress class %s)", bandwidthLimit, ip, classID, ifbClassID)
	return nil
}

// removePeerBandwidthLimit removes TC rules for a specific peer IP
func removePeerBandwidthLimit(peerIP string) error {
	// Parse the IP to get just the IP address
	ip := peerIP
	if strings.Contains(peerIP, "/") {
		parsedIP, _, err := net.ParseCIDR(peerIP)
		if err != nil {
			return fmt.Errorf("failed to parse peer IP: %v", err)
		}
		ip = parsedIP.String()
	}

	// Generate the class ID based on the IP
	ipParts := strings.Split(ip, ".")
	if len(ipParts) != 4 {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	lastOctet := ipParts[3]
	classID := fmt.Sprintf("1:%s", lastOctet)

	// Remove filters for this IP
	// List all filters to find the ones for this class
	cmd := exec.Command("tc", "filter", "show", "dev", interfaceName, "parent", "1:")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Failed to list filters for peer IP %s: %v, output: %s", ip, err, string(output))
	} else {
		// Parse the output to find filter handles that match this classID
		// The output format includes lines like:
		// filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:4
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			// Look for lines containing our flowid (classID)
			if strings.Contains(line, "flowid "+classID) && strings.Contains(line, "fh ") {
				// Extract handle (format: fh 800::800)
				parts := strings.Fields(line)
				var handle string
				for j, part := range parts {
					if part == "fh" && j+1 < len(parts) {
						handle = parts[j+1]
						break
					}
				}
				if handle != "" {
					// Delete this filter using the handle
					delCmd := exec.Command("tc", "filter", "del", "dev", interfaceName, "parent", "1:", "handle", handle, "prio", "1", "u32")
					if delOutput, delErr := delCmd.CombinedOutput(); delErr != nil {
						logger.Debug("Failed to delete filter handle %s for peer IP %s: %v, output: %s", handle, ip, delErr, string(delOutput))
					} else {
						logger.Debug("Deleted filter handle %s for peer IP %s", handle, ip)
					}
				}
			}
		}
	}

	// Remove the egress class on wg0
	cmd = exec.Command("tc", "class", "del", "dev", interfaceName, "classid", classID)
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "No such file or directory") && !strings.Contains(string(output), "Cannot find") {
			logger.Warn("Failed to remove egress class for peer IP %s: %v, output: %s", ip, err, string(output))
		}
	}

	// Remove the ingress class and filters on the IFB device
	ifbClassID := fmt.Sprintf("2:%s", lastOctet)

	// Check if the ifb kernel module is loaded (works inside containers too)
	if _, err := os.Stat("/sys/module/ifb"); os.IsNotExist(err) {
		logger.Warn("IFB module not loaded, skipping IFB setup and ingress traffic shaping")
		logger.Info("Removed bandwidth limit for peer IP %s (egress class %s, ingress class %s)", ip, classID, ifbClassID)
		return nil
	}

	cmd = exec.Command("tc", "filter", "show", "dev", ifbName, "parent", "2:")
	output, err = cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Failed to list IFB filters for peer IP %s: %v, output: %s", ip, err, string(output))
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "flowid "+ifbClassID) && strings.Contains(line, "fh ") {
				parts := strings.Fields(line)
				var handle string
				for j, part := range parts {
					if part == "fh" && j+1 < len(parts) {
						handle = parts[j+1]
						break
					}
				}
				if handle != "" {
					delCmd := exec.Command("tc", "filter", "del", "dev", ifbName, "parent", "2:", "handle", handle, "prio", "1", "u32")
					if delOutput, delErr := delCmd.CombinedOutput(); delErr != nil {
						logger.Debug("Failed to delete IFB filter handle %s for peer IP %s: %v, output: %s", handle, ip, delErr, string(delOutput))
					} else {
						logger.Debug("Deleted IFB filter handle %s for peer IP %s", handle, ip)
					}
				}
			}
		}
	}

	cmd = exec.Command("tc", "class", "del", "dev", ifbName, "classid", ifbClassID)
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "No such file or directory") && !strings.Contains(string(output), "Cannot find") {
			logger.Warn("Failed to remove IFB class for peer IP %s: %v, output: %s", ip, err, string(output))
		}
	}

	logger.Info("Removed bandwidth limit for peer IP %s (egress class %s, ingress class %s)", ip, classID, ifbClassID)
	return nil
}
