package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/gerbil/internal/metrics"
	"github.com/fosrl/gerbil/logger"
	"github.com/patrickmn/go-cache"
)

// RouteRecord represents a routing configuration
type RouteRecord struct {
	Hostname   string
	TargetHost string
	TargetPort int
}

// RouteAPIResponse represents the response from the route API
type RouteAPIResponse struct {
	Endpoints []string `json:"endpoints"`
}

// ProxyProtocolInfo holds information parsed from incoming PROXY protocol header
type ProxyProtocolInfo struct {
	Protocol     string // TCP4 or TCP6
	SrcIP        string
	DestIP       string
	SrcPort      int
	DestPort     int
	OriginalConn net.Conn // The original connection after PROXY protocol parsing
}

// SNIProxy represents the main proxy server
type SNIProxy struct {
	port            int
	cache           *cache.Cache
	listener        net.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	localProxyAddr  string
	localProxyPort  int
	remoteConfigURL string
	publicKey       string
	proxyProtocol   bool // Enable PROXY protocol v1

	// New fields for fast local SNI lookup
	localSNIs     map[string]struct{}
	localSNIsLock sync.RWMutex

	// Local overrides for domains that should always use local proxy
	localOverrides map[string]struct{}

	// Track active tunnels by SNI
	activeTunnels     map[string]*activeTunnel
	activeTunnelsLock sync.Mutex

	// Trusted upstream proxies that can send PROXY protocol
	trustedUpstreams map[string]struct{}

	// Reusable HTTP client for API requests
	httpClient *http.Client

	// Buffer pool for connection piping
	bufferPool *sync.Pool
}

type activeTunnel struct {
	conns []net.Conn
}

// readOnlyConn is a wrapper for io.Reader that implements net.Conn
type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

// parseProxyProtocolHeader parses a PROXY protocol v1 header from the connection
func (p *SNIProxy) parseProxyProtocolHeader(conn net.Conn) (*ProxyProtocolInfo, net.Conn, error) {
	// Check if the connection comes from a trusted upstream
	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, conn, fmt.Errorf("failed to parse remote address: %w", err)
	}

	// Resolve the remote IP to hostname to check if it's trusted
	// For simplicity, we'll check the IP directly in trusted upstreams
	// In production, you might want to do reverse DNS lookup
	if _, isTrusted := p.trustedUpstreams[remoteHost]; !isTrusted {
		// Not from trusted upstream, return original connection
		return nil, conn, nil
	}

	// Set read timeout for PROXY protocol parsing
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, conn, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read the first line (PROXY protocol header)
	buffer := make([]byte, 512) // PROXY protocol header should be much smaller
	n, err := conn.Read(buffer)
	if err != nil {
		// If we can't read from trusted upstream, treat as regular connection
		logger.Debug("Could not read from trusted upstream %s, treating as regular connection: %v", remoteHost, err)
		// Clear read timeout before returning
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			logger.Debug("Failed to clear read deadline: %v", clearErr)
		}
		return nil, conn, nil
	}

	// Find the end of the first line (CRLF)
	headerEnd := bytes.Index(buffer[:n], []byte("\r\n"))
	if headerEnd == -1 {
		// No PROXY protocol header found, treat as regular TLS connection
		// Return the connection with the buffered data prepended
		logger.Debug("No PROXY protocol header from trusted upstream %s, treating as regular TLS connection", remoteHost)

		// Clear read timeout
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			logger.Debug("Failed to clear read deadline: %v", err)
		}

		// Create a reader that includes the buffered data + original connection
		newReader := io.MultiReader(bytes.NewReader(buffer[:n]), conn)
		wrappedConn := &proxyProtocolConn{
			Conn:   conn,
			reader: newReader,
		}
		return nil, wrappedConn, nil
	}

	headerLine := string(buffer[:headerEnd])
	remainingData := buffer[headerEnd+2 : n]

	// Parse PROXY protocol line: "PROXY TCP4/TCP6 srcIP destIP srcPort destPort"
	parts := strings.Fields(headerLine)
	if len(parts) != 6 || parts[0] != "PROXY" {
		// Check for PROXY UNKNOWN
		if len(parts) == 2 && parts[0] == "PROXY" && parts[1] == "UNKNOWN" {
			// PROXY UNKNOWN - use original connection info
			return nil, conn, nil
		}
		// Invalid PROXY protocol, but might be regular TLS - treat as such
		logger.Debug("Invalid PROXY protocol from trusted upstream %s, treating as regular TLS connection: %s", remoteHost, headerLine)

		// Clear read timeout
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			logger.Debug("Failed to clear read deadline: %v", err)
		}

		// Return the connection with all buffered data prepended
		newReader := io.MultiReader(bytes.NewReader(buffer[:n]), conn)
		wrappedConn := &proxyProtocolConn{
			Conn:   conn,
			reader: newReader,
		}
		return nil, wrappedConn, nil
	}

	protocol := parts[1]
	srcIP := parts[2]
	destIP := parts[3]
	srcPort, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, conn, fmt.Errorf("invalid source port in PROXY header: %s", parts[4])
	}
	destPort, err := strconv.Atoi(parts[5])
	if err != nil {
		return nil, conn, fmt.Errorf("invalid destination port in PROXY header: %s", parts[5])
	}

	// Create a new reader that includes remaining data + original connection
	var newReader io.Reader
	if len(remainingData) > 0 {
		newReader = io.MultiReader(bytes.NewReader(remainingData), conn)
	} else {
		newReader = conn
	}

	// Create a wrapper connection that reads from the combined reader
	wrappedConn := &proxyProtocolConn{
		Conn:   conn,
		reader: newReader,
	}

	proxyInfo := &ProxyProtocolInfo{
		Protocol:     protocol,
		SrcIP:        srcIP,
		DestIP:       destIP,
		SrcPort:      srcPort,
		DestPort:     destPort,
		OriginalConn: wrappedConn,
	}

	// Clear read timeout
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, conn, fmt.Errorf("failed to clear read deadline: %w", err)
	}

	return proxyInfo, wrappedConn, nil
}

// proxyProtocolConn wraps a connection to read from a custom reader
type proxyProtocolConn struct {
	net.Conn
	reader io.Reader
}

func (c *proxyProtocolConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// buildProxyProtocolHeaderFromInfo creates a PROXY protocol v1 header using ProxyProtocolInfo
func (p *SNIProxy) buildProxyProtocolHeaderFromInfo(proxyInfo *ProxyProtocolInfo, targetAddr net.Addr) string {
	targetTCP, ok := targetAddr.(*net.TCPAddr)
	if !ok {
		// Fallback for unknown address types
		return "PROXY UNKNOWN\r\n"
	}

	// Use the original client information from the PROXY protocol
	var targetIP string
	var protocol string

	// Parse source IP to determine protocol family
	srcIP := net.ParseIP(proxyInfo.SrcIP)
	if srcIP == nil {
		return "PROXY UNKNOWN\r\n"
	}

	if srcIP.To4() != nil {
		// Source is IPv4, use TCP4 protocol
		protocol = "TCP4"
		if targetTCP.IP.To4() != nil {
			// Target is also IPv4, use as-is
			targetIP = targetTCP.IP.String()
		} else {
			// Target is IPv6, but we need IPv4 for consistent protocol family
			if targetTCP.IP.IsLoopback() {
				targetIP = "127.0.0.1"
			} else {
				targetIP = "127.0.0.1" // Safe fallback
			}
		}
	} else {
		// Source is IPv6, use TCP6 protocol
		protocol = "TCP6"
		if targetTCP.IP.To4() != nil {
			// Target is IPv4, convert to IPv6 representation
			targetIP = "::ffff:" + targetTCP.IP.String()
		} else {
			// Target is also IPv6, use as-is
			targetIP = targetTCP.IP.String()
		}
	}

	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		protocol,
		proxyInfo.SrcIP,
		targetIP,
		proxyInfo.SrcPort,
		targetTCP.Port)
}

// buildProxyProtocolHeader creates a PROXY protocol v1 header
func buildProxyProtocolHeader(clientAddr, targetAddr net.Addr) string {
	clientTCP, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		// Fallback for unknown address types
		return "PROXY UNKNOWN\r\n"
	}

	targetTCP, ok := targetAddr.(*net.TCPAddr)
	if !ok {
		// Fallback for unknown address types
		return "PROXY UNKNOWN\r\n"
	}

	// Determine protocol family based on client IP and normalize target IP accordingly
	var protocol string
	var targetIP string

	if clientTCP.IP.To4() != nil {
		// Client is IPv4, use TCP4 protocol
		protocol = "TCP4"
		if targetTCP.IP.To4() != nil {
			// Target is also IPv4, use as-is
			targetIP = targetTCP.IP.String()
		} else {
			// Target is IPv6, but we need IPv4 for consistent protocol family
			// Use the IPv4 loopback if target is IPv6 loopback, otherwise use 127.0.0.1
			if targetTCP.IP.IsLoopback() {
				targetIP = "127.0.0.1"
			} else {
				// For non-loopback IPv6 targets, we could try to extract embedded IPv4
				// or fall back to a sensible IPv4 address based on the target
				targetIP = "127.0.0.1" // Safe fallback
			}
		}
	} else {
		// Client is IPv6, use TCP6 protocol
		protocol = "TCP6"
		if targetTCP.IP.To4() != nil {
			// Target is IPv4, convert to IPv6 representation
			targetIP = "::ffff:" + targetTCP.IP.String()
		} else {
			// Target is also IPv6, use as-is
			targetIP = targetTCP.IP.String()
		}
	}

	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		protocol,
		clientTCP.IP.String(),
		targetIP,
		clientTCP.Port,
		targetTCP.Port)
}

// NewSNIProxy creates a new SNI proxy instance
func NewSNIProxy(port int, remoteConfigURL, publicKey, localProxyAddr string, localProxyPort int, localOverrides []string, proxyProtocol bool, trustedUpstreams []string) (*SNIProxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create local overrides map
	overridesMap := make(map[string]struct{})
	for _, domain := range localOverrides {
		if domain != "" {
			overridesMap[domain] = struct{}{}
		}
	}

	// Create trusted upstreams map
	trustedMap := make(map[string]struct{})
	for _, upstream := range trustedUpstreams {
		if upstream != "" {
			// Add both the domain and potentially resolved IPs
			trustedMap[upstream] = struct{}{}

			// Try to resolve the domain to IPs and add them too
			if ips, err := net.LookupIP(upstream); err == nil {
				for _, ip := range ips {
					trustedMap[ip.String()] = struct{}{}
				}
			}
		}
	}

	proxy := &SNIProxy{
		port:             port,
		cache:            cache.New(3*time.Second, 10*time.Minute),
		ctx:              ctx,
		cancel:           cancel,
		localProxyAddr:   localProxyAddr,
		localProxyPort:   localProxyPort,
		remoteConfigURL:  remoteConfigURL,
		publicKey:        publicKey,
		proxyProtocol:    proxyProtocol,
		localSNIs:        make(map[string]struct{}),
		localOverrides:   overridesMap,
		activeTunnels:    make(map[string]*activeTunnel),
		trustedUpstreams: trustedMap,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		bufferPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024)
				return &buf
			},
		},
	}

	return proxy, nil
}

// Start begins listening for connections
func (p *SNIProxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", p.port, err)
	}

	p.listener = listener
	logger.Debug("SNI Proxy listening on port %d", p.port)

	// Accept connections in a goroutine
	go p.acceptConnections()

	return nil
}

// Stop gracefully shuts down the proxy
func (p *SNIProxy) Stop() error {
	log.Println("Stopping SNI Proxy...")

	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All connections closed gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Timeout waiting for connections to close")
	}

	log.Println("SNI Proxy stopped")
	return nil
}

// acceptConnections handles incoming connections
func (p *SNIProxy) acceptConnections() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				logger.Debug("Accept error: %v", err)
				continue
			}
		}

		p.wg.Add(1)
		go p.handleConnection(conn)
	}
}

// readClientHello reads and parses the TLS ClientHello message
func (p *SNIProxy) readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()
	if hello == nil {
		return nil, err
	}
	return hello, nil
}

// peekClientHello reads the ClientHello while preserving the data for forwarding
func (p *SNIProxy) peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := p.readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

// extractSNI extracts the SNI hostname from the TLS ClientHello
func (p *SNIProxy) extractSNI(conn net.Conn) (string, io.Reader, error) {
	clientHello, clientReader, err := p.peekClientHello(conn)
	if err != nil {
		return "", nil, fmt.Errorf("failed to peek ClientHello: %w", err)
	}

	if clientHello.ServerName == "" {
		return "", clientReader, fmt.Errorf("no SNI hostname found in ClientHello")
	}

	return clientHello.ServerName, clientReader, nil
}

// handleConnection processes a single client connection
func (p *SNIProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	metrics.RecordSNIConnection("accepted")

	logger.Debug("Accepted connection from %s", clientConn.RemoteAddr())

	// Check for PROXY protocol from trusted upstream
	var proxyInfo *ProxyProtocolInfo
	var actualClientConn net.Conn = clientConn

	if len(p.trustedUpstreams) > 0 {
		var err error
		proxyInfo, actualClientConn, err = p.parseProxyProtocolHeader(clientConn)
		if err != nil {
			metrics.RecordSNIProxyProtocolParseError()
			logger.Debug("Failed to parse PROXY protocol: %v", err)
			return
		}
		if proxyInfo != nil {
			metrics.RecordSNITrustedProxyEvent("proxy_protocol_parsed")
			logger.Debug("Received PROXY protocol from trusted upstream: %s:%d -> %s:%d",
				proxyInfo.SrcIP, proxyInfo.SrcPort, proxyInfo.DestIP, proxyInfo.DestPort)
		} else {
			// No PROXY protocol detected, but connection is from trusted upstream
			// This is fine - treat as regular connection
			logger.Debug("No PROXY protocol detected from trusted upstream, treating as regular connection")
		}
	}

	// Set read timeout for SNI extraction
	if err := actualClientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logger.Debug("Failed to set read deadline: %v", err)
		return
	}

	// Extract SNI hostname
	clientHelloStart := time.Now()
	hostname, clientReader, err := p.extractSNI(actualClientConn)
	if err != nil {
		logger.Debug("SNI extraction failed: %v", err)
		return
	}
	metrics.RecordProxyTLSHandshake(hostname, time.Since(clientHelloStart).Seconds())

	if hostname == "" {
		log.Println("No SNI hostname found")
		return
	}

	logger.Debug("SNI hostname detected: %s", hostname)

	// Remove read timeout for normal operation
	if err := actualClientConn.SetReadDeadline(time.Time{}); err != nil {
		logger.Debug("Failed to clear read deadline: %v", err)
		return
	}

	// Get routing information - use original client address if available from PROXY protocol
	var clientAddrStr string
	if proxyInfo != nil {
		clientAddrStr = fmt.Sprintf("%s:%d", proxyInfo.SrcIP, proxyInfo.SrcPort)
	} else {
		clientAddrStr = clientConn.RemoteAddr().String()
	}

	route, err := p.getRoute(hostname, clientAddrStr)
	if err != nil {
		logger.Debug("Failed to get route for %s: %v", hostname, err)
		return
	}

	if route == nil {
		logger.Debug("No route found for hostname: %s", hostname)
		return
	}

	logger.Debug("Routing %s to %s:%d", hostname, route.TargetHost, route.TargetPort)

	// Connect to target server
	targetConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", route.TargetHost, route.TargetPort),
		10*time.Second)
	if err != nil {
		logger.Debug("Failed to connect to target %s:%d: %v",
			route.TargetHost, route.TargetPort, err)
		return
	}
	defer targetConn.Close()

	logger.Debug("Connected to target: %s:%d", route.TargetHost, route.TargetPort)
	metrics.RecordActiveProxyConnection(hostname, 1)
	defer metrics.RecordActiveProxyConnection(hostname, -1)

	// Send PROXY protocol header if enabled
	if p.proxyProtocol {
		var proxyHeader string
		if proxyInfo != nil {
			// Use original client info from PROXY protocol
			proxyHeader = p.buildProxyProtocolHeaderFromInfo(proxyInfo, targetConn.LocalAddr())
		} else {
			// Use direct client connection info
			proxyHeader = buildProxyProtocolHeader(clientConn.RemoteAddr(), targetConn.LocalAddr())
		}
		logger.Debug("Sending PROXY protocol header: %s", strings.TrimSpace(proxyHeader))

		if _, err := targetConn.Write([]byte(proxyHeader)); err != nil {
			logger.Debug("Failed to send PROXY protocol header: %v", err)
			return
		}
	}

	// Track this tunnel by SNI
	p.activeTunnelsLock.Lock()
	tunnel, ok := p.activeTunnels[hostname]
	if !ok {
		tunnel = &activeTunnel{}
		p.activeTunnels[hostname] = tunnel
	}
	tunnel.conns = append(tunnel.conns, actualClientConn)
	p.activeTunnelsLock.Unlock()

	defer func() {
		// Remove this conn from active tunnels
		p.activeTunnelsLock.Lock()
		if tunnel, ok := p.activeTunnels[hostname]; ok {
			newConns := make([]net.Conn, 0, len(tunnel.conns))
			for _, c := range tunnel.conns {
				if c != actualClientConn {
					newConns = append(newConns, c)
				}
			}
			if len(newConns) == 0 {
				delete(p.activeTunnels, hostname)
			} else {
				tunnel.conns = newConns
			}
		}
		p.activeTunnelsLock.Unlock()
	}()

	// Start bidirectional data transfer
	p.pipe(hostname, actualClientConn, targetConn, clientReader)
}

// getRoute retrieves routing information for a hostname
func (p *SNIProxy) getRoute(hostname, clientAddr string) (*RouteRecord, error) {
	// Check local overrides first
	if _, isOverride := p.localOverrides[hostname]; isOverride {
		logger.Debug("Local override matched for hostname: %s", hostname)
		metrics.RecordProxyRouteLookup("local_override", hostname)
		return &RouteRecord{
			Hostname:   hostname,
			TargetHost: p.localProxyAddr,
			TargetPort: p.localProxyPort,
		}, nil
	}

	// Fast path: check if hostname is in localSNIs
	p.localSNIsLock.RLock()
	_, isLocal := p.localSNIs[hostname]
	p.localSNIsLock.RUnlock()
	if isLocal {
		metrics.RecordProxyRouteLookup("local", hostname)
		return &RouteRecord{
			Hostname:   hostname,
			TargetHost: p.localProxyAddr,
			TargetPort: p.localProxyPort,
		}, nil
	}

	// Check cache first
	if cached, found := p.cache.Get(hostname); found {
		if cached == nil {
			metrics.RecordProxyRouteLookup("cached_not_found", hostname)
			return nil, nil // Cached negative result
		}
		logger.Debug("Cache hit for hostname: %s", hostname)
		metrics.RecordProxyRouteLookup("cache_hit", hostname)
		return cached.(*RouteRecord), nil
	}

	logger.Debug("Cache miss for hostname: %s, querying API", hostname)
	metrics.RecordProxyRouteLookup("cache_miss", hostname)

	// Query API with timeout
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()

	// Construct API URL (without hostname in path)
	apiURL := fmt.Sprintf("%s/gerbil/get-resolved-hostname", p.remoteConfigURL)

	// Create request body with hostname and public key
	requestBody := map[string]string{
		"hostname":  hostname,
		"publicKey": p.publicKey,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Make HTTP request
	apiStart := time.Now()
	// Make HTTP request using reusable client
	apiStart := time.Now()
	resp, err := p.httpClient.Do(req)
	if err != nil {
		metrics.RecordSNIRouteAPIRequest("error")
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()
	metrics.RecordSNIRouteAPILatency(time.Since(apiStart).Seconds())

	if resp.StatusCode == http.StatusNotFound {
		metrics.RecordSNIRouteAPIRequest("not_found")
		// Cache negative result for shorter time (1 minute)
		p.cache.Set(hostname, nil, 1*time.Minute)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		metrics.RecordSNIRouteAPIRequest("error")
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	metrics.RecordSNIRouteAPIRequest("success")

	// Parse response
	var apiResponse RouteAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	endpoints := apiResponse.Endpoints

	// Default target configuration
	targetHost := p.localProxyAddr
	targetPort := p.localProxyPort

	// If no endpoints returned, use local node
	if len(endpoints) == 0 {
		logger.Debug("No endpoints returned for hostname: %s, using local node", hostname)
	} else {
		// Select endpoint using consistent hashing for stickiness
		selectedEndpoint := p.selectStickyEndpoint(clientAddr, endpoints)
		targetHost = selectedEndpoint
		targetPort = 443 // Default HTTPS port
		logger.Debug("Selected endpoint %s for hostname %s from client %s", selectedEndpoint, hostname, clientAddr)
	}

	route := &RouteRecord{
		Hostname:   hostname,
		TargetHost: targetHost,
		TargetPort: targetPort,
	}

	// Cache the result
	p.cache.Set(hostname, route, cache.DefaultExpiration)
	logger.Debug("Cached route for hostname: %s", hostname)

	return route, nil
}

// selectStickyEndpoint selects an endpoint using consistent hashing to ensure
// the same client always routes to the same endpoint for load balancing
func (p *SNIProxy) selectStickyEndpoint(clientAddr string, endpoints []string) string {
	if len(endpoints) == 0 {
		return p.localProxyAddr
	}
	if len(endpoints) == 1 {
		return endpoints[0]
	}

	// Use FNV hash for consistent selection based on client address
	hash := fnv.New32a()
	hash.Write([]byte(clientAddr))
	index := hash.Sum32() % uint32(len(endpoints))

	return endpoints[index]
}

// pipe handles bidirectional data transfer between connections
func (p *SNIProxy) pipe(hostname string, clientConn, targetConn net.Conn, clientReader io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	// closeOnce ensures we only close connections once
	var closeOnce sync.Once
	closeConns := func() {
		closeOnce.Do(func() {
			// Close both connections to unblock any pending reads
			clientConn.Close()
			targetConn.Close()
		})
	}

	// Copy data from client to target (using the buffered reader)
	go func() {
		defer wg.Done()
		defer closeConns()

		// Get buffer from pool and return when done
		bufPtr := p.bufferPool.Get().(*[]byte)
		defer func() {
			// Clear buffer before returning to pool to prevent data leakage
			clear(*bufPtr)
			p.bufferPool.Put(bufPtr)
		}()

		bytesCopied, err := io.CopyBuffer(targetConn, clientReader, *bufPtr)
		metrics.RecordProxyBytesTransmitted(hostname, "client_to_target", bytesCopied)
		if err != nil && err != io.EOF {
			logger.Debug("Copy client->target error: %v", err)
		}
	}()

	// Copy data from target to client
	go func() {
		defer wg.Done()
		defer closeConns()

		// Get buffer from pool and return when done
		bufPtr := p.bufferPool.Get().(*[]byte)
		defer func() {
			// Clear buffer before returning to pool to prevent data leakage
			clear(*bufPtr)
			p.bufferPool.Put(bufPtr)
		}()

		bytesCopied, err := io.CopyBuffer(clientConn, targetConn, *bufPtr)
		metrics.RecordProxyBytesTransmitted(hostname, "target_to_client", bytesCopied)
		if err != nil && err != io.EOF {
			logger.Debug("Copy target->client error: %v", err)
		}
	}()

	wg.Wait()
}

// GetCacheStats returns cache statistics
func (p *SNIProxy) GetCacheStats() (int, int) {
	return p.cache.ItemCount(), len(p.cache.Items())
}

// ClearCache clears all cached entries
func (p *SNIProxy) ClearCache() {
	p.cache.Flush()
	log.Println("Cache cleared")
}

// UpdateLocalSNIs updates the local SNIs and invalidates cache for changed domains
func (p *SNIProxy) UpdateLocalSNIs(fullDomains []string) {
	newSNIs := make(map[string]struct{})
	for _, domain := range fullDomains {
		newSNIs[domain] = struct{}{}
		// Invalidate any cached route for this domain
		p.cache.Delete(domain)
	}

	// Update localSNIs
	p.localSNIsLock.Lock()
	removed := make([]string, 0)
	for sni := range p.localSNIs {
		if _, stillLocal := newSNIs[sni]; !stillLocal {
			removed = append(removed, sni)
		}
	}
	p.localSNIs = newSNIs
	p.localSNIsLock.Unlock()

	logger.Debug("Updated local SNIs, added %d, removed %d", len(newSNIs), len(removed))

	// Terminate tunnels for removed SNIs
	if len(removed) > 0 {
		p.activeTunnelsLock.Lock()
		for _, sni := range removed {
			if tunnels, ok := p.activeTunnels[sni]; ok {
				for _, conn := range tunnels.conns {
					conn.Close()
				}
				delete(p.activeTunnels, sni)
				logger.Debug("Closed tunnels for SNI target change: %s", sni)
			}
		}
		p.activeTunnelsLock.Unlock()
	}
}
