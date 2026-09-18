package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/gerbil/internal/metrics"
	"github.com/fosrl/gerbil/logger"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const relayIfname = "relay"

type EncryptedHolePunchMessage struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

type HolePunchMessage struct {
	OlmID     string `json:"olmId"`
	NewtID    string `json:"newtId"`
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
}

type ClientEndpoint struct {
	OlmID             string `json:"olmId"`
	NewtID            string `json:"newtId"`
	Token             string `json:"token"`
	IP                string `json:"ip"`
	Port              int    `json:"port"`
	Timestamp         int64  `json:"timestamp"`
	ReachableAt       string `json:"reachableAt"`
	ExitNodePublicKey string `json:"exitNodePublicKey"`
	ClientPublicKey   string `json:"publicKey"`
}

// Updated to support multiple destination peers
type ProxyMapping struct {
	Destinations []PeerDestination `json:"destinations"`
	LastUsed     time.Time         `json:"-"` // Not serialized, used for cleanup
}

type PeerDestination struct {
	DestinationIP   string `json:"destinationIP"`
	DestinationPort int    `json:"destinationPort"`
}

type DestinationConn struct {
	conn *net.UDPConn
	// lastUsed is unix nanoseconds, read/written via atomic ops since it's
	// touched from packet workers and the response goroutine concurrently
	// with no lock, and is also scanned for LRU eviction below.
	lastUsed atomic.Int64
}

// defaultMaxUDPConnections caps the number of concurrent per-peer outbound
// UDP sockets the relay will keep open in s.connections. Without a cap, a
// burst of peer churn creates sockets faster than the 5-minute idle cleanup
// can reap them, exhausting the host's ephemeral port range or fd ulimit.
// That surfaces as "dial udp ...: resource temporarily unavailable" on every
// subsequent packet and pegs the CPU logging the flood (outage 2026-07-03,
// recurrence 2026-07-05). Overridable via GERBIL_MAX_UDP_CONNECTIONS.
const defaultMaxUDPConnections = 8192

var maxUDPConnections = loadMaxUDPConnections()

func loadMaxUDPConnections() int64 {
	if v := os.Getenv("GERBIL_MAX_UDP_CONNECTIONS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxUDPConnections
}

// Type for storing WireGuard handshake information
type WireGuardSession struct {
	mu            sync.RWMutex
	ReceiverIndex uint32
	SenderIndex   uint32
	DestAddr      *net.UDPAddr
	LastSeen      time.Time
}

// GetSenderIndex returns the SenderIndex in a thread-safe manner
func (s *WireGuardSession) GetSenderIndex() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SenderIndex
}

// GetDestAddr returns the DestAddr in a thread-safe manner
func (s *WireGuardSession) GetDestAddr() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.DestAddr
}

// GetLastSeen returns the LastSeen timestamp in a thread-safe manner
func (s *WireGuardSession) GetLastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastSeen
}

// UpdateLastSeen updates the LastSeen timestamp in a thread-safe manner
func (s *WireGuardSession) UpdateLastSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// Type for tracking bidirectional communication patterns to rebuild sessions
type CommunicationPattern struct {
	FromClient     *net.UDPAddr // The client address
	ToDestination  *net.UDPAddr // The destination address
	ClientIndex    uint32       // The receiver index seen from client
	DestIndex      uint32       // The receiver index seen from destination
	LastFromClient time.Time    // Last packet from client to destination
	LastFromDest   time.Time    // Last packet from destination to client
	PacketCount    int          // Number of packets observed
}

type InitialMappings struct {
	Mappings map[string]ProxyMapping `json:"mappings"` // key is "ip:port"
}

// Packet is a simple struct to hold the packet data and sender info.
type Packet struct {
	data       []byte
	remoteAddr *net.UDPAddr
	n          int
}

// holePunchRateLimitEntry tracks hole punch message counts within a sliding 1-second window.
type holePunchRateLimitEntry struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
}

// WireGuard message types
const (
	WireGuardMessageTypeHandshakeInitiation = 1
	WireGuardMessageTypeHandshakeResponse   = 2
	WireGuardMessageTypeCookieReply         = 3
	WireGuardMessageTypeTransportData       = 4
)

// cachedEndpointState holds the last-known endpoint fields used for change detection.
// Timestamp is intentionally excluded since it always changes.
type cachedEndpointState struct {
	OlmID     string
	NewtID    string
	Token     string
	IP        string
	Port      int
	PublicKey string
}

// cachedEndpointEntry wraps cachedEndpointState with a timestamp so the cache
// can be expired after a short TTL even when the endpoint fields are unchanged.
type cachedEndpointEntry struct {
	state    cachedEndpointState
	cachedAt time.Time
}

// --- End Types ---

// bufferPool allows reusing buffers to reduce allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500)
	},
}

// UDPProxyServer has a channel for incoming packets.
type UDPProxyServer struct {
	addr          string
	serverURL     string
	conn          *net.UDPConn
	proxyMappings sync.Map // map[string]ProxyMapping where key is "ip:port"
	connections   sync.Map // map[string]*DestinationConn where key is destination "ip:port"
	// connectionCount mirrors len(connections) without an O(n) sync.Map walk,
	// so the cap check in getOrCreateConnection is cheap on the hot path.
	connectionCount atomic.Int64
	privateKey      wgtypes.Key
	packetChan      chan Packet
	ctx             context.Context
	cancel          context.CancelFunc
	// stopOnce ensures Stop() is idempotent: packetChan is closed at most once
	// even when Stop() is called concurrently or multiple times (e.g. via both
	// defer and the shutdown goroutine in main).
	stopOnce sync.Once

	// Session tracking for WireGuard peers
	// Key format: "senderIndex:receiverIndex"
	wgSessions sync.Map
	// Session index for O(1) lookup by receiver index
	// Key: receiverIndex (uint32), Value: *WireGuardSession
	sessionsByReceiverIndex sync.Map
	// Communication pattern tracking for rebuilding sessions
	// Key format: "clientIP:clientPort-destIP:destPort"
	commPatterns sync.Map
	// Rate limiter for encrypted hole punch messages, keyed by "ip:port"
	holePunchRateLimiter sync.Map
	// Cache for resolved UDP addresses to avoid per-packet DNS lookups
	// Key: "ip:port" string, Value: *net.UDPAddr
	addrCache sync.Map
	// lastEndpointCache stores the last-known endpoint state per client (key: olmId:newtId)
	// used to skip redundant HTTP notifications when nothing has changed.
	lastEndpointCache sync.Map
	// notifyChan is the async queue for hole-punch endpoint notifications.
	// Dedicated notifier workers drain this channel and perform the HTTP call.
	notifyChan chan ClientEndpoint
	// ReachableAt is the URL where this server can be reached
	ReachableAt string
}

// NewUDPProxyServer initializes the server with a buffered packet channel and derived context.
func NewUDPProxyServer(parentCtx context.Context, addr, serverURL string, privateKey wgtypes.Key, reachableAt string) *UDPProxyServer {
	ctx, cancel := context.WithCancel(parentCtx)
	return &UDPProxyServer{
		addr:        addr,
		serverURL:   serverURL,
		privateKey:  privateKey,
		packetChan:  make(chan Packet, 50000), // Increased from 1000 to handle high throughput
		notifyChan:  make(chan ClientEndpoint, 1000),
		ReachableAt: reachableAt,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start sets up the UDP listener, worker pool, and begins reading packets.
func (s *UDPProxyServer) Start() error {
	// Fetch initial mappings asynchronously so a large (potentially 100MB+)
	// response does not block the UDP listener from coming up. Any packets
	// arriving for unknown mappings before the load completes will simply
	// log and be repopulated via the hole-punch path.
	go func() {
		if err := s.fetchInitialMappings(); err != nil {
			logger.Error("Failed to fetch initial mappings: %v", err)
		}
	}()

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	logger.Info("UDP server listening on %s", s.addr)

	// Start worker goroutines based on CPU cores for better parallelism
	// At high throughput (160+ Mbps), we need many workers to avoid bottlenecks
	workerCount := runtime.NumCPU() * 10
	if workerCount < 20 {
		workerCount = 20 // Minimum 20 workers
	}
	logger.Info("Starting %d packet workers (CPUs: %d)", workerCount, runtime.NumCPU())
	for i := 0; i < workerCount; i++ {
		go s.packetWorker()
	}

	// Start the goroutine that reads packets from the UDP socket.
	go s.readPackets()

	// Start the idle connection cleanup routine.
	go s.cleanupIdleConnections()

	// Start the session cleanup routine
	go s.cleanupIdleSessions()

	// Start the proxy mapping cleanup routine
	go s.cleanupIdleProxyMappings()

	// Start the communication pattern cleanup routine
	go s.cleanupIdleCommunicationPatterns()

	// Start the hole punch rate limiter cleanup routine
	go s.cleanupHolePunchRateLimiter()

	// Start async endpoint notifier workers (HTTP calls off the hot path)
	for i := 0; i < 5; i++ {
		go s.endpointNotifierWorker()
	}

	return nil
}

// Stop shuts down the UDPProxyServer. It is safe to call multiple times
// and from concurrent goroutines; the internal cleanup runs at most once.
func (s *UDPProxyServer) Stop() {
	s.stopOnce.Do(func() {
		// Signal all background goroutines to stop
		if s.cancel != nil {
			s.cancel()
		}
		// Close listener to unblock reads
		if s.conn != nil {
			_ = s.conn.Close()
		}
		// Close all downstream UDP connections
		s.connections.Range(func(key, value interface{}) bool {
			if dc, ok := value.(*DestinationConn); ok && dc.conn != nil {
				_ = dc.conn.Close()
			}
			return true
		})
		// Close packet channel to unblock and stop all packetWorker goroutines.
		// This must happen after cancel() so that readPackets() exits cleanly
		// and no further sends to packetChan occur before we close it.
		close(s.packetChan)
	})
}

// readPackets continuously reads from the UDP socket and pushes packets into the channel.
func (s *UDPProxyServer) readPackets() {
	for {
		// Exit promptly if context is canceled
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		buf := bufferPool.Get().([]byte)
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// If we're shutting down, exit
			select {
			case <-s.ctx.Done():
				bufferPool.Put(buf[:1500])
				return
			default:
				logger.Error("Error reading UDP packet: %v", err)
				bufferPool.Put(buf[:1500])
				continue
			}
		}
		s.packetChan <- Packet{data: buf[:n], remoteAddr: remoteAddr, n: n}
	}
}

// packetWorker processes incoming packets from the channel.
func (s *UDPProxyServer) packetWorker() {
	for packet := range s.packetChan {
		// Determine packet type by inspecting the first byte.
		if packet.n > 0 && packet.data[0] >= 1 && packet.data[0] <= 4 {
			metrics.RecordUDPPacket(relayIfname, "wireguard", "in")
			metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(packet.n))
			// Process as a WireGuard packet.
			s.handleWireGuardPacket(packet.data, packet.remoteAddr)
		} else {
			metrics.RecordUDPPacket(relayIfname, "hole_punch", "in")
			metrics.RecordUDPPacketSize(relayIfname, "hole_punch", float64(packet.n))
			// Rate limit: allow at most 2 hole punch messages per IP:Port per second
			rateLimitKey := packet.remoteAddr.String()
			entryVal, _ := s.holePunchRateLimiter.LoadOrStore(rateLimitKey, &holePunchRateLimitEntry{
				windowStart: time.Now(),
			})
			rlEntry := entryVal.(*holePunchRateLimitEntry)
			rlEntry.mu.Lock()
			now := time.Now()
			if now.Sub(rlEntry.windowStart) >= time.Second {
				rlEntry.count = 0
				rlEntry.windowStart = now
			}
			rlEntry.count++
			allowed := rlEntry.count <= 2
			rlEntry.mu.Unlock()
			if !allowed {
				// logger.Debug("Rate limiting hole punch message from %s", rateLimitKey)
				metrics.RecordHolePunchEvent(relayIfname, "rate_limited")
				bufferPool.Put(packet.data[:1500])
				continue
			}

			// Process as an encrypted hole punch message
			var encMsg EncryptedHolePunchMessage
			if err := json.Unmarshal(packet.data, &encMsg); err != nil {
				logger.Error("Error unmarshaling encrypted message: %v", err)
				metrics.RecordHolePunchEvent(relayIfname, "error")
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			if encMsg.EphemeralPublicKey == "" {
				logger.Error("Received malformed message without ephemeral key")
				metrics.RecordHolePunchEvent(relayIfname, "error")
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			// This appears to be an encrypted message
			decryptedData, err := s.decryptMessage(encMsg)
			if err != nil {
				// logger.Error("Failed to decrypt message: %v", err)
				metrics.RecordHolePunchEvent(relayIfname, "error")
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			// Process the decrypted hole punch message
			var msg HolePunchMessage
			if err := json.Unmarshal(decryptedData, &msg); err != nil {
				logger.Error("Error unmarshaling decrypted message: %v", err)
				metrics.RecordHolePunchEvent(relayIfname, "error")
				// Return the buffer to the pool for reuse and continue with next packet
				bufferPool.Put(packet.data[:1500])
				continue
			}

			endpoint := ClientEndpoint{
				NewtID:            msg.NewtID,
				OlmID:             msg.OlmID,
				Token:             msg.Token,
				IP:                packet.remoteAddr.IP.String(),
				Port:              packet.remoteAddr.Port,
				Timestamp:         time.Now().Unix(),
				ReachableAt:       s.ReachableAt,
				ExitNodePublicKey: s.privateKey.PublicKey().String(),
				ClientPublicKey:   msg.PublicKey,
			}
			logger.Debug("Created endpoint from packet remoteAddr %s: IP=%s, Port=%d", packet.remoteAddr.String(), endpoint.IP, endpoint.Port)

			// Check if anything meaningful changed before queuing an HTTP notification.
			// The cache expires after 2.5 s so the server always receives a fresh
			// timestamp within its 5-second staleness window.
			const endpointCacheTTL = 2500 * time.Millisecond
			cacheKey := endpoint.OlmID + ":" + endpoint.NewtID
			newState := cachedEndpointState{
				OlmID:     endpoint.OlmID,
				NewtID:    endpoint.NewtID,
				Token:     endpoint.Token,
				IP:        endpoint.IP,
				Port:      endpoint.Port,
				PublicKey: endpoint.ClientPublicKey,
			}
			if cached, ok := s.lastEndpointCache.Load(cacheKey); ok {
				entry := cached.(cachedEndpointEntry)
				if entry.state == newState && time.Since(entry.cachedAt) < endpointCacheTTL {
					// Endpoint unchanged and cache still fresh - skip the HTTP call.
					logger.Debug("Endpoint unchanged for %s, skipping notification", cacheKey)
					metrics.RecordHolePunchEvent(relayIfname, "deduplicated")
					s.clearSessionsForIP(endpoint.IP)
					metrics.RecordHolePunchEvent(relayIfname, "success")
					bufferPool.Put(packet.data[:1500])
					continue
				}
			}
			s.lastEndpointCache.Store(cacheKey, cachedEndpointEntry{state: newState, cachedAt: time.Now()})

			// Queue the notification asynchronously so the hot path is not blocked by HTTP.
			select {
			case s.notifyChan <- endpoint:
			case <-s.ctx.Done():
				// shutting down
			default:
				logger.Debug("Notification queue full, dropping hole punch notification for %s:%d", endpoint.IP, endpoint.Port)
				metrics.RecordHolePunchEvent(relayIfname, "queue_full")
			}
			s.clearSessionsForIP(endpoint.IP) // Clear sessions for this IP to allow re-establishment
			metrics.RecordHolePunchEvent(relayIfname, "success")
		}
		// Return the buffer to the pool for reuse.
		bufferPool.Put(packet.data[:1500])
	}
}

// endpointNotifierWorker drains the notifyChan and performs the HTTP notification for each
// hole-punch endpoint. Running several of these keeps latency low even when the server is slow.
func (s *UDPProxyServer) endpointNotifierWorker() {
	for {
		select {
		case endpoint, ok := <-s.notifyChan:
			if !ok {
				return
			}
			s.notifyServer(endpoint)
		case <-s.ctx.Done():
			return
		}
	}
}

// decryptMessage decrypts the message using the server's private key
func (s *UDPProxyServer) decryptMessage(encMsg EncryptedHolePunchMessage) ([]byte, error) {
	// Parse the ephemeral public key
	ephPubKey, err := wgtypes.ParseKey(encMsg.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %v", err)
	}

	// Use X25519 for key exchange instead of ScalarMult
	sharedSecret, err := curve25519.X25519(s.privateKey[:], ephPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %v", err)
	}

	// Create the AEAD cipher using the shared secret
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %v", err)
	}

	// Verify nonce size
	if len(encMsg.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size")
	}

	// Decrypt the ciphertext
	plaintext, err := aead.Open(nil, encMsg.Nonce, encMsg.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}

func (s *UDPProxyServer) fetchInitialMappings() error {
	logger.Info("Requesting initial proxy mappings")
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s"}`, s.privateKey.PublicKey().String())))
	resp, err := http.Post(s.serverURL+"/gerbil/get-all-relays", "application/json", body)
	if err != nil {
		return fmt.Errorf("failed to fetch mappings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned non-OK status: %d, body: %s",
			resp.StatusCode, string(body))
	}
	logger.Info("Received initial mappings, streaming decode")

	// Stream-decode the response instead of buffering the entire body
	// (which can be 100MB+) and then re-walking it with json.Unmarshal.
	// This both lowers peak memory and lets us start populating the
	// sync.Map as entries arrive.
	dec := json.NewDecoder(bufio.NewReaderSize(resp.Body, 1<<20))

	// Expect opening '{' of the top-level object.
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("failed to read opening token: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected '{' at top level, got %v", tok)
	}

	count := 0
	now := time.Now()

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("failed to read top-level key: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected string key at top level, got %T", keyTok)
		}

		if key != "mappings" {
			// Skip unknown top-level fields without materializing them.
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("failed to skip field %q: %v", key, err)
			}
			continue
		}

		// Expect opening '{' of the mappings object.
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("failed to read mappings open: %v", err)
		}
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return fmt.Errorf("expected '{' for mappings, got %v", tok)
		}

		for dec.More() {
			mapKeyTok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("failed to read mapping key: %v", err)
			}
			mapKey, ok := mapKeyTok.(string)
			if !ok {
				return fmt.Errorf("expected string mapping key, got %T", mapKeyTok)
			}

			var mapping ProxyMapping
			if err := dec.Decode(&mapping); err != nil {
				return fmt.Errorf("failed to decode mapping %q: %v", mapKey, err)
			}
			mapping.LastUsed = now
			s.proxyMappings.Store(mapKey, mapping)
			count++
		}

		// Consume closing '}' of mappings object.
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("failed to read mappings close: %v", err)
		}
	}

	metrics.RecordProxyInitialMappings(relayIfname, int64(count))
	metrics.RecordProxyMapping(relayIfname, int64(count))
	logger.Info("Loaded %d initial proxy mappings", count)
	return nil
}

// Extract WireGuard message indices
func extractWireGuardIndices(packet []byte) (uint32, uint32, bool) {
	if len(packet) < 12 {
		return 0, 0, false
	}

	messageType := packet[0]
	if messageType == WireGuardMessageTypeHandshakeInitiation {
		// Handshake initiation: extract sender index at offset 4
		senderIndex := binary.LittleEndian.Uint32(packet[4:8])
		return 0, senderIndex, true
	} else if messageType == WireGuardMessageTypeHandshakeResponse {
		// Handshake response: extract sender index at offset 4 and receiver index at offset 8
		senderIndex := binary.LittleEndian.Uint32(packet[4:8])
		receiverIndex := binary.LittleEndian.Uint32(packet[8:12])
		return receiverIndex, senderIndex, true
	} else if messageType == WireGuardMessageTypeTransportData {
		// Transport data: extract receiver index at offset 4
		receiverIndex := binary.LittleEndian.Uint32(packet[4:8])
		return receiverIndex, 0, true
	}

	return 0, 0, false
}

// cachedAddr holds a resolved UDP address with TTL
type cachedAddr struct {
	addr      *net.UDPAddr
	expiresAt time.Time
}

// addrCacheTTL is how long resolved addresses are cached before re-resolving
const addrCacheTTL = 5 * time.Minute

// getCachedAddr returns a cached UDP address or resolves and caches it.
// This avoids per-packet DNS lookups which are a major throughput bottleneck.
func (s *UDPProxyServer) getCachedAddr(ip string, port int) (*net.UDPAddr, error) {
	key := fmt.Sprintf("%s:%d", ip, port)

	// Check cache first
	if cached, ok := s.addrCache.Load(key); ok {
		entry := cached.(*cachedAddr)
		if time.Now().Before(entry.expiresAt) {
			return entry.addr, nil
		}
		// Cache expired, delete and re-resolve
		s.addrCache.Delete(key)
	}

	// Resolve and cache
	addr, err := net.ResolveUDPAddr("udp", key)
	if err != nil {
		return nil, err
	}

	s.addrCache.Store(key, &cachedAddr{
		addr:      addr,
		expiresAt: time.Now().Add(addrCacheTTL),
	})
	return addr, nil
}

// Updated to handle multi-peer WireGuard communication
func (s *UDPProxyServer) handleWireGuardPacket(packet []byte, remoteAddr *net.UDPAddr) {
	if len(packet) == 0 {
		logger.Error("Received empty packet")
		return
	}

	messageType := packet[0]
	receiverIndex, senderIndex, ok := extractWireGuardIndices(packet)

	if !ok {
		logger.Error("Failed to extract WireGuard indices")
		return
	}

	key := remoteAddr.String()
	mappingObj, ok := s.proxyMappings.Load(key)
	if !ok {
		logger.Error("No proxy mapping found for %s", key)
		return
	}

	proxyMapping := mappingObj.(ProxyMapping)
	// Update the last used timestamp and store it back
	proxyMapping.LastUsed = time.Now()
	s.proxyMappings.Store(key, proxyMapping)

	// Handle different WireGuard message types
	switch messageType {
	case WireGuardMessageTypeHandshakeInitiation:
		// Initial handshake: forward to all peers
		logger.Debug("Forwarding handshake initiation from %s (sender index: %d) to peers %v", remoteAddr, senderIndex, proxyMapping.Destinations)

		for _, dest := range proxyMapping.Destinations {
			destAddr, err := s.getCachedAddr(dest.DestinationIP, dest.DestinationPort)
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Debug("Failed to forward handshake initiation: %v", err)
				metrics.RecordProxyConnectionError(relayIfname, "write_udp")
				continue
			}
			metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
			metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(len(packet)))
		}

	case WireGuardMessageTypeHandshakeResponse:
		// Received handshake response: establish session mapping
		logger.Debug("Received handshake response with receiver index %d and sender index %d from %s",
			receiverIndex, senderIndex, remoteAddr)

		// Create a session key for the peer that sent the initial handshake
		sessionKey := fmt.Sprintf("%d:%d", receiverIndex, senderIndex)

		// Store the session information
		session := &WireGuardSession{
			ReceiverIndex: receiverIndex,
			SenderIndex:   senderIndex,
			DestAddr:      remoteAddr,
			LastSeen:      time.Now(),
		}
		if _, loaded := s.wgSessions.LoadOrStore(sessionKey, session); loaded {
			s.wgSessions.Store(sessionKey, session)
		} else {
			metrics.RecordSession(relayIfname, 1)
		}
		// Also index by sender index for O(1) lookup in transport data path
		s.sessionsByReceiverIndex.Store(senderIndex, session)

		// Forward the response to the original sender
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := s.getCachedAddr(dest.DestinationIP, dest.DestinationPort)
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward handshake response: %v", err)
				metrics.RecordProxyConnectionError(relayIfname, "write_udp")
				continue
			}
			metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
			metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(len(packet)))
		}

	case WireGuardMessageTypeTransportData:
		// Data packet: forward only to the established session peer
		// logger.Debug("Received transport data with receiver index %d from %s", receiverIndex, remoteAddr)

		// Look up the session based on the receiver index - O(1) lookup instead of O(n) Range
		var destAddr *net.UDPAddr

		// Fast path: direct index lookup by receiver index
		if sessionObj, ok := s.sessionsByReceiverIndex.Load(receiverIndex); ok {
			session := sessionObj.(*WireGuardSession)
			destAddr = session.GetDestAddr()
			session.UpdateLastSeen()
		}

		if destAddr != nil {
			// We found a specific peer to forward to
			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				return
			}

			// Track communication pattern for session rebuilding
			s.trackCommunicationPattern(remoteAddr, destAddr, receiverIndex, true)

			_, err = conn.Write(packet)
			if err != nil {
				logger.Debug("Failed to forward transport data: %v", err)
				metrics.RecordProxyConnectionError(relayIfname, "write_udp")
				return
			}
			metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
			metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(len(packet)))
		} else {
			// No known session, fall back to forwarding to all peers
			logger.Debug("No session found for receiver index %d, forwarding to all destinations", receiverIndex)
			for _, dest := range proxyMapping.Destinations {
				destAddr, err := s.getCachedAddr(dest.DestinationIP, dest.DestinationPort)
				if err != nil {
					logger.Error("Failed to resolve destination address: %v", err)
					continue
				}

				conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
				if err != nil {
					logger.Error("Failed to get/create connection: %v", err)
					continue
				}

				// Track communication pattern for session rebuilding
				s.trackCommunicationPattern(remoteAddr, destAddr, receiverIndex, true)

				_, err = conn.Write(packet)
				if err != nil {
					logger.Debug("Failed to forward transport data: %v", err)
					metrics.RecordProxyConnectionError(relayIfname, "write_udp")
					continue
				}
				metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
				metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(len(packet)))
			}
		}

	default:
		// Other packet types (like cookie reply)
		logger.Debug("Forwarding WireGuard packet type %d from %s", messageType, remoteAddr)

		// Forward to all peers
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := s.getCachedAddr(dest.DestinationIP, dest.DestinationPort)
			if err != nil {
				logger.Error("Failed to resolve destination address: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, remoteAddr)
			if err != nil {
				logger.Error("Failed to get/create connection: %v", err)
				continue
			}

			_, err = conn.Write(packet)
			if err != nil {
				logger.Error("Failed to forward WireGuard packet: %v", err)
				metrics.RecordProxyConnectionError(relayIfname, "write_udp")
				continue
			}
			metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
			metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(len(packet)))
		}
	}
}

func (s *UDPProxyServer) getOrCreateConnection(destAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (*net.UDPConn, error) {
	key := destAddr.String() + "-" + remoteAddr.String()

	// Check if we have an existing connection
	if conn, ok := s.connections.Load(key); ok {
		destConn := conn.(*DestinationConn)
		destConn.lastUsed.Store(time.Now().UnixNano())
		return destConn.conn, nil
	}

	// Enforce a hard cap on concurrent sockets so a burst of peer churn can't
	// exhaust the host's ephemeral ports/fds. Evict the least-recently-used
	// connection to make room instead of growing unbounded.
	if s.connectionCount.Load() >= maxUDPConnections {
		s.evictLRUConnection()
	}

	// Create new connection
	newConn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		metrics.RecordProxyConnectionError(relayIfname, "dial_udp")
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	destConn := &DestinationConn{conn: newConn}
	destConn.lastUsed.Store(time.Now().UnixNano())

	// Store the new connection. If another goroutine raced us and already
	// created one for this key, close ours and use theirs instead.
	if existing, loaded := s.connections.LoadOrStore(key, destConn); loaded {
		newConn.Close()
		return existing.(*DestinationConn).conn, nil
	}
	s.connectionCount.Add(1)
	metrics.RecordUDPConnection(relayIfname, 1)

	// Start a goroutine to handle responses
	go s.handleResponses(newConn, destAddr, remoteAddr)

	return newConn, nil
}

// evictLRUConnection closes and removes the least-recently-used destination
// connection so a new one can be created under the concurrent connection cap.
func (s *UDPProxyServer) evictLRUConnection() {
	var oldestKey interface{}
	var oldestConn *DestinationConn
	var oldestTime int64

	s.connections.Range(func(key, value interface{}) bool {
		destConn := value.(*DestinationConn)
		lu := destConn.lastUsed.Load()
		if oldestKey == nil || lu < oldestTime {
			oldestKey = key
			oldestConn = destConn
			oldestTime = lu
		}
		return true
	})

	if oldestKey != nil {
		s.connections.Delete(oldestKey)
		oldestConn.conn.Close()
		s.connectionCount.Add(-1)
		metrics.RecordUDPConnection(relayIfname, -1)
		metrics.RecordProxyCleanupRemoved(relayIfname, "conn_evicted", 1)
	}
}

func (s *UDPProxyServer) handleResponses(conn *net.UDPConn, destAddr *net.UDPAddr, remoteAddr *net.UDPAddr) {
	buffer := make([]byte, 1500)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("Error reading response from %s: %v", destAddr.String(), err)
			return
		}
		metrics.RecordUDPPacket(relayIfname, "wireguard", "in")
		metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(n))

		// Process the response to track sessions if it's a WireGuard packet
		if n > 0 && buffer[0] >= 1 && buffer[0] <= 4 {
			receiverIndex, senderIndex, ok := extractWireGuardIndices(buffer[:n])
			if ok && buffer[0] == WireGuardMessageTypeHandshakeResponse {
				// Store the session mapping for the handshake response
				sessionKey := fmt.Sprintf("%d:%d", senderIndex, receiverIndex)
				session := &WireGuardSession{
					ReceiverIndex: receiverIndex,
					SenderIndex:   senderIndex,
					DestAddr:      destAddr,
					LastSeen:      time.Now(),
				}
				if _, loaded := s.wgSessions.LoadOrStore(sessionKey, session); loaded {
					s.wgSessions.Store(sessionKey, session)
				} else {
					metrics.RecordSession(relayIfname, 1)
				}
				// Also index by sender index for O(1) lookup
				s.sessionsByReceiverIndex.Store(senderIndex, session)
				logger.Debug("Stored session mapping: %s -> %s", sessionKey, destAddr.String())
			} else if ok && buffer[0] == WireGuardMessageTypeTransportData {
				// Track communication pattern for session rebuilding (reverse direction)
				s.trackCommunicationPattern(destAddr, remoteAddr, receiverIndex, false)
			}
		}

		// Forward the response back through the main listener
		_, err = s.conn.WriteToUDP(buffer[:n], remoteAddr)
		if err != nil {
			logger.Error("Failed to forward response: %v", err)
			metrics.RecordProxyConnectionError(relayIfname, "write_udp")
			continue
		}
		metrics.RecordUDPPacket(relayIfname, "wireguard", "out")
		metrics.RecordUDPPacketSize(relayIfname, "wireguard", float64(n))
	}
}

// Add a cleanup method to periodically remove idle connections
func (s *UDPProxyServer) cleanupIdleConnections() {
	// Ticker interval and idle threshold were previously 5min/10min, meaning
	// a socket could sit open for up to 15 minutes after going idle. Under a
	// reconnect/churn burst that lag is enough to exhaust ephemeral ports
	// before cleanup catches up, so both are tightened here.
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupStart := time.Now()
			now := time.Now().UnixNano()
			removed := int64(0)
			s.connections.Range(func(key, value interface{}) bool {
				destConn := value.(*DestinationConn)
				if now-destConn.lastUsed.Load() > int64(5*time.Minute) {
					destConn.conn.Close()
					s.connections.Delete(key)
					removed++
				}
				return true
			})
			if removed > 0 {
				s.connectionCount.Add(-removed)
				metrics.RecordUDPConnection(relayIfname, -removed)
				metrics.RecordProxyCleanupRemoved(relayIfname, "conn", removed)
			}
			metrics.RecordProxyIdleCleanupDuration(relayIfname, "conn", time.Since(cleanupStart).Seconds())
		case <-s.ctx.Done():
			return
		}
	}
}

// New method to periodically remove idle sessions
func (s *UDPProxyServer) cleanupIdleSessions() {
	ticker := time.NewTicker(5 * time.Minute)

	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupStart := time.Now()
			now := time.Now()
			s.wgSessions.Range(func(key, value interface{}) bool {
				session := value.(*WireGuardSession)
				// Use thread-safe method to read LastSeen
				if now.Sub(session.GetLastSeen()) > 15*time.Minute {
					s.wgSessions.Delete(key)
					metrics.RecordSession(relayIfname, -1)
					metrics.RecordProxyCleanupRemoved(relayIfname, "session", 1)
					logger.Debug("Removed idle session: %s", key)
				}
				return true
			})
			metrics.RecordProxyIdleCleanupDuration(relayIfname, "session", time.Since(cleanupStart).Seconds())
		case <-s.ctx.Done():
			return
		}
	}
}

// New method to periodically remove idle proxy mappings
func (s *UDPProxyServer) cleanupIdleProxyMappings() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupStart := time.Now()
			now := time.Now()
			s.proxyMappings.Range(func(key, value interface{}) bool {
				mapping := value.(ProxyMapping)
				// Remove mappings that haven't been used in 30 minutes
				if now.Sub(mapping.LastUsed) > 30*time.Minute {
					s.proxyMappings.Delete(key)
					metrics.RecordProxyMapping(relayIfname, -1)
					metrics.RecordProxyCleanupRemoved(relayIfname, "proxy_mapping", 1)
					logger.Debug("Removed idle proxy mapping: %s", key)
				}
				return true
			})
			metrics.RecordProxyIdleCleanupDuration(relayIfname, "proxy_mapping", time.Since(cleanupStart).Seconds())
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *UDPProxyServer) notifyServer(endpoint ClientEndpoint) {
	logger.Debug("notifyServer called with endpoint: IP=%s, Port=%d", endpoint.IP, endpoint.Port)

	jsonData, err := json.Marshal(endpoint)
	if err != nil {
		logger.Error("Failed to marshal endpoint data: %v", err)
		return
	}

	resp, err := http.Post(s.serverURL+"/gerbil/update-hole-punch", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error("Failed to notify server: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Server returned non-OK status: %d, body: %s",
			resp.StatusCode, string(body))
		return
	}

	// Parse the proxy mapping response
	var mapping ProxyMapping
	if err := json.NewDecoder(resp.Body).Decode(&mapping); err != nil {
		logger.Error("Failed to decode proxy mapping: %v", err)
		return
	}

	logger.Debug("Received proxy mapping from server: %v", mapping)

	// Store the mapping with current timestamp
	key := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)
	logger.Debug("About to store proxy mapping with key: %s (from endpoint IP=%s, Port=%d)", key, endpoint.IP, endpoint.Port)
	mapping.LastUsed = time.Now()
	if _, existed := s.proxyMappings.Load(key); existed {
		metrics.RecordProxyMappingUpdate(relayIfname)
	} else {
		metrics.RecordProxyMapping(relayIfname, 1)
	}
	s.proxyMappings.Store(key, mapping)

	logger.Debug("Stored proxy mapping for %s with %d destinations (timestamp: %v)", key, len(mapping.Destinations), mapping.LastUsed)
}

// Updated to support multiple destinations
func (s *UDPProxyServer) UpdateProxyMapping(sourceIP string, sourcePort int, destinations []PeerDestination) {
	key := fmt.Sprintf("%s:%d", sourceIP, sourcePort)
	mapping := ProxyMapping{
		Destinations: destinations,
		LastUsed:     time.Now(),
	}
	if _, existed := s.proxyMappings.Load(key); existed {
		metrics.RecordProxyMappingUpdate(relayIfname)
	} else {
		metrics.RecordProxyMapping(relayIfname, 1)
	}
	s.proxyMappings.Store(key, mapping)
}

// OnPeerAdded clears connections and sessions for a specific WireGuard IP to allow re-establishment
func (s *UDPProxyServer) OnPeerAdded(wgIP string) {
	logger.Info("Clearing connections for added peer with WG IP: %s", wgIP)
	s.clearConnectionsForWGIP(wgIP)
	// s.clearSessionsForWGIP(wgIP) THE DEST ADDR IS NOT THE WG IP, SO THIS IS NOT NEEDED
	// s.clearProxyMappingsForWGIP(wgIP)
}

// OnPeerRemoved clears connections and sessions for a specific WireGuard IP
func (s *UDPProxyServer) OnPeerRemoved(wgIP string) {
	logger.Info("Clearing connections for removed peer with WG IP: %s", wgIP)
	s.clearConnectionsForWGIP(wgIP)
	// s.clearSessionsForWGIP(wgIP) THE DEST ADDR IS NOT THE WG IP, SO THIS IS NOT NEEDED
	// s.clearProxyMappingsForWGIP(wgIP)
}

// clearConnectionsForWGIP removes all connections associated with a specific WireGuard IP
func (s *UDPProxyServer) clearConnectionsForWGIP(wgIP string) {
	var keysToDelete []string

	s.connections.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		destConn := value.(*DestinationConn)

		// Connection keys are in format "destAddr-remoteAddr"
		// Check if either destination or remote address contains the WG IP
		if containsIP(keyStr, wgIP) {
			keysToDelete = append(keysToDelete, keyStr)
			destConn.conn.Close()
			logger.Debug("Closing connection for WG IP %s: %s", wgIP, keyStr)
		}
		return true
	})

	// Delete the connections
	for _, key := range keysToDelete {
		s.connections.Delete(key)
	}
	if len(keysToDelete) > 0 {
		s.connectionCount.Add(-int64(len(keysToDelete)))
		metrics.RecordUDPConnection(relayIfname, -int64(len(keysToDelete)))
	}

	logger.Info("Cleared %d connections for WG IP: %s", len(keysToDelete), wgIP)
}

// clearSessionsForWGIP removes all WireGuard sessions associated with a specific WireGuard IP
func (s *UDPProxyServer) clearSessionsForIP(ip string) {
	var keysToDelete []string

	s.wgSessions.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		session := value.(*WireGuardSession)

		// Check if the session's destination address contains the WG IP (thread-safe)
		destAddr := session.GetDestAddr()
		if destAddr != nil && destAddr.IP.String() == ip {
			keysToDelete = append(keysToDelete, keyStr)
			logger.Debug("Marking session for deletion for WG IP %s: %s", ip, keyStr)
		}
		return true
	})

	// Delete the sessions
	for _, key := range keysToDelete {
		s.wgSessions.Delete(key)
	}
	if len(keysToDelete) > 0 {
		metrics.RecordSession(relayIfname, -int64(len(keysToDelete)))
		metrics.RecordProxyCleanupRemoved(relayIfname, "session", int64(len(keysToDelete)))
	}

	logger.Debug("Cleared %d sessions for WG IP: %s", len(keysToDelete), ip)
}

// // clearProxyMappingsForWGIP removes all proxy mappings that have destinations pointing to a specific WireGuard IP
// func (s *UDPProxyServer) clearProxyMappingsForWGIP(wgIP string) {
// 	var keysToDelete []string

// 	s.proxyMappings.Range(func(key, value interface{}) bool {
// 		keyStr := key.(string)
// 		mapping := value.(ProxyMapping)

// 		// Check if any destination in the mapping contains the WG IP
// 		for _, dest := range mapping.Destinations {
// 			if dest.DestinationIP == wgIP {
// 				keysToDelete = append(keysToDelete, keyStr)
// 				logger.Debug("Marking proxy mapping for deletion for WG IP %s: %s -> %s:%d", wgIP, keyStr, dest.DestinationIP, dest.DestinationPort)
// 				break // Found one destination, no need to check others in this mapping
// 			}
// 		}
// 		return true
// 	})

// 	// Delete the proxy mappings
// 	for _, key := range keysToDelete {
// 		s.proxyMappings.Delete(key)
// 		logger.Debug("Deleted proxy mapping: %s", key)
// 	}

// 	logger.Info("Cleared %d proxy mappings for WG IP: %s", len(keysToDelete), wgIP)
// }

// containsIP checks if a connection key string contains the specified IP address
func containsIP(connectionKey, ip string) bool {
	// Connection keys are in format "destIP:destPort-remoteIP:remotePort"
	// Check if the IP appears at the beginning (destination) or after the dash (remote)
	ipWithColon := ip + ":"

	// Check if connection key starts with the IP (destination address)
	if len(connectionKey) >= len(ipWithColon) && connectionKey[:len(ipWithColon)] == ipWithColon {
		return true
	}

	// Check if connection key contains the IP after a dash (remote address)
	dashIndex := -1
	for i := 0; i < len(connectionKey); i++ {
		if connectionKey[i] == '-' {
			dashIndex = i
			break
		}
	}

	if dashIndex != -1 && dashIndex+1 < len(connectionKey) {
		remainingPart := connectionKey[dashIndex+1:]
		if len(remainingPart) >= len(ip)+1 && remainingPart[:len(ip)+1] == ipWithColon {
			return true
		}
	}

	return false
}

// UpdateDestinationInMappings updates all proxy mappings that contain the old destination with the new destination
// Returns the number of mappings that were updated
func (s *UDPProxyServer) UpdateDestinationInMappings(oldDest, newDest PeerDestination) int {
	updatedCount := 0

	s.proxyMappings.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		mapping := value.(ProxyMapping)
		updated := false

		// Check each destination in the mapping
		for i, dest := range mapping.Destinations {
			if dest.DestinationIP == oldDest.DestinationIP && dest.DestinationPort == oldDest.DestinationPort {
				// Update this destination
				mapping.Destinations[i] = newDest
				updated = true
				logger.Debug("Updated destination in mapping %s: %s:%d -> %s:%d",
					keyStr, oldDest.DestinationIP, oldDest.DestinationPort,
					newDest.DestinationIP, newDest.DestinationPort)
			}
		}

		// If we updated any destinations, store the updated mapping back
		if updated {
			mapping.LastUsed = time.Now()
			s.proxyMappings.Store(keyStr, mapping)
			updatedCount++
		}

		return true // continue iteration
	})

	if updatedCount > 0 {
		logger.Info("Updated %d proxy mappings from %s:%d to %s:%d",
			updatedCount, oldDest.DestinationIP, oldDest.DestinationPort,
			newDest.DestinationIP, newDest.DestinationPort)
	}

	return updatedCount
}

// trackCommunicationPattern tracks bidirectional communication patterns to rebuild sessions
func (s *UDPProxyServer) trackCommunicationPattern(fromAddr, toAddr *net.UDPAddr, receiverIndex uint32, fromClient bool) {
	var clientAddr, destAddr *net.UDPAddr
	var clientIndex, destIndex uint32

	if fromClient {
		clientAddr = fromAddr
		destAddr = toAddr
		clientIndex = receiverIndex
		destIndex = 0 // We don't know the destination index yet
	} else {
		clientAddr = toAddr
		destAddr = fromAddr
		clientIndex = 0 // We don't know the client index yet
		destIndex = receiverIndex
	}

	patternKey := fmt.Sprintf("%s-%s", clientAddr.String(), destAddr.String())
	now := time.Now()

	if existingPattern, ok := s.commPatterns.Load(patternKey); ok {
		pattern := existingPattern.(*CommunicationPattern)

		// Update the pattern
		if fromClient {
			pattern.LastFromClient = now
			if pattern.ClientIndex == 0 {
				pattern.ClientIndex = clientIndex
			}
		} else {
			pattern.LastFromDest = now
			if pattern.DestIndex == 0 {
				pattern.DestIndex = destIndex
			}
		}

		pattern.PacketCount++
		s.commPatterns.Store(patternKey, pattern)

		// Check if we have bidirectional communication and can rebuild a session
		s.tryRebuildSession(pattern)
	} else {
		// Create new pattern
		pattern := &CommunicationPattern{
			FromClient:    clientAddr,
			ToDestination: destAddr,
			ClientIndex:   clientIndex,
			DestIndex:     destIndex,
			PacketCount:   1,
		}

		if fromClient {
			pattern.LastFromClient = now
		} else {
			pattern.LastFromDest = now
		}

		if _, loaded := s.commPatterns.LoadOrStore(patternKey, pattern); !loaded {
			metrics.RecordCommPattern(relayIfname, 1)
		}
	}
}

// tryRebuildSession attempts to rebuild a WireGuard session from communication patterns
func (s *UDPProxyServer) tryRebuildSession(pattern *CommunicationPattern) {
	// Require both indices and a minimum amount of bidirectional traffic
	if pattern.ClientIndex == 0 || pattern.DestIndex == 0 || pattern.PacketCount < 4 {
		return
	}

	// Check if we have bidirectional communication within a reasonable time window
	timeDiff := pattern.LastFromClient.Sub(pattern.LastFromDest)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff >= 30*time.Second {
		return
	}

	sessionKey := fmt.Sprintf("%d:%d", pattern.DestIndex, pattern.ClientIndex)
	destStr := pattern.ToDestination.String()

	// Fast path: if a matching session already exists, just refresh LastSeen and bail out.
	// This prevents log spam and repeated work for every packet of an established flow.
	if existing, ok := s.wgSessions.Load(sessionKey); ok {
		sess := existing.(*WireGuardSession)
		if da := sess.GetDestAddr(); da != nil && da.String() == destStr {
			sess.UpdateLastSeen()
			// Make sure the receiver-index fast-path is populated so future packets
			// don't keep falling back to broadcast + pattern tracking.
			if _, indexed := s.sessionsByReceiverIndex.Load(pattern.ClientIndex); !indexed {
				s.sessionsByReceiverIndex.Store(pattern.ClientIndex, sess)
			}
			return
		}
	}

	// Create or replace the session mapping
	session := &WireGuardSession{
		ReceiverIndex: pattern.DestIndex,
		SenderIndex:   pattern.ClientIndex,
		DestAddr:      pattern.ToDestination,
		LastSeen:      time.Now(),
	}
	if _, loaded := s.wgSessions.LoadOrStore(sessionKey, session); loaded {
		s.wgSessions.Store(sessionKey, session)
	} else {
		metrics.RecordSession(relayIfname, 1)
		metrics.RecordSessionRebuilt(relayIfname)
	}
	// Index by client receiver index so the transport-data fast path can find it.
	s.sessionsByReceiverIndex.Store(pattern.ClientIndex, session)

	logger.Info("Rebuilt WireGuard session from communication pattern: %s -> %s (packets: %d)",
		sessionKey, destStr, pattern.PacketCount)
}

// cleanupIdleCommunicationPatterns periodically removes idle communication patterns
// cleanupHolePunchRateLimiter periodically evicts stale rate limit entries to prevent unbounded growth.
func (s *UDPProxyServer) cleanupHolePunchRateLimiter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.holePunchRateLimiter.Range(func(key, value interface{}) bool {
				rlEntry := value.(*holePunchRateLimitEntry)
				rlEntry.mu.Lock()
				stale := now.Sub(rlEntry.windowStart) > 10*time.Second
				rlEntry.mu.Unlock()
				if stale {
					s.holePunchRateLimiter.Delete(key)
				}
				return true
			})
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *UDPProxyServer) cleanupIdleCommunicationPatterns() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupStart := time.Now()
			now := time.Now()
			s.commPatterns.Range(func(key, value interface{}) bool {
				pattern := value.(*CommunicationPattern)

				// Get the most recent activity
				lastActivity := pattern.LastFromClient
				if pattern.LastFromDest.After(lastActivity) {
					lastActivity = pattern.LastFromDest
				}

				// Remove patterns that haven't had activity in 20 minutes
				if now.Sub(lastActivity) > 20*time.Minute {
					s.commPatterns.Delete(key)
					metrics.RecordCommPattern(relayIfname, -1)
					metrics.RecordProxyCleanupRemoved(relayIfname, "comm_pattern", 1)
					logger.Debug("Removed idle communication pattern: %s", key)
				}
				return true
			})
			metrics.RecordProxyIdleCleanupDuration(relayIfname, "comm_pattern", time.Since(cleanupStart).Seconds())
		case <-s.ctx.Done():
			return
		}
	}
}
