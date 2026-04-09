package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
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
	conn     *net.UDPConn
	lastUsed time.Time
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
	privateKey    wgtypes.Key
	packetChan    chan Packet
	ctx           context.Context
	cancel        context.CancelFunc

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
		ReachableAt: reachableAt,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start sets up the UDP listener, worker pool, and begins reading packets.
func (s *UDPProxyServer) Start() error {
	// Fetch initial mappings.
	if err := s.fetchInitialMappings(); err != nil {
		return fmt.Errorf("failed to fetch initial mappings: %v", err)
	}

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

	return nil
}

func (s *UDPProxyServer) Stop() {
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
	// Close packet channel to stop workers
	select {
	case <-s.ctx.Done():
	default:
	}
	close(s.packetChan)
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
			s.notifyServer(endpoint)
			s.clearSessionsForIP(endpoint.IP) // Clear sessions for this IP to allow re-establishment
			metrics.RecordHolePunchEvent(relayIfname, "success")
		}
		// Return the buffer to the pool for reuse.
		bufferPool.Put(packet.data[:1500])
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	logger.Info("Received initial mappings: %s", string(data))
	var initialMappings InitialMappings
	if err := json.Unmarshal(data, &initialMappings); err != nil {
		return fmt.Errorf("failed to unmarshal initial mappings: %v", err)
	}
	// Store mappings in our sync.Map.
	for key, mapping := range initialMappings.Mappings {
		// Initialize LastUsed timestamp for initial mappings
		mapping.LastUsed = time.Now()
		s.proxyMappings.Store(key, mapping)
	}
	metrics.RecordProxyInitialMappings(relayIfname, int64(len(initialMappings.Mappings)))
	metrics.RecordProxyMapping(relayIfname, int64(len(initialMappings.Mappings)))
	logger.Info("Loaded %d initial proxy mappings", len(initialMappings.Mappings))
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
		destConn.lastUsed = time.Now()
		return destConn.conn, nil
	}

	// Create new connection
	newConn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		metrics.RecordProxyConnectionError(relayIfname, "dial_udp")
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	// Store the new connection
	s.connections.Store(key, &DestinationConn{
		conn:     newConn,
		lastUsed: time.Now(),
	})

	// Start a goroutine to handle responses
	go s.handleResponses(newConn, destAddr, remoteAddr)

	return newConn, nil
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
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupStart := time.Now()
			now := time.Now()
			s.connections.Range(func(key, value interface{}) bool {
				destConn := value.(*DestinationConn)
				if now.Sub(destConn.lastUsed) > 10*time.Minute {
					destConn.conn.Close()
					s.connections.Delete(key)
					metrics.RecordProxyCleanupRemoved(relayIfname, "conn", 1)
				}
				return true
			})
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
	// Check if we have bidirectional communication within a reasonable time window
	timeDiff := pattern.LastFromClient.Sub(pattern.LastFromDest)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	// Only rebuild if we have recent bidirectional communication and both indices
	if timeDiff < 30*time.Second && pattern.ClientIndex != 0 && pattern.DestIndex != 0 && pattern.PacketCount >= 4 {
		// Create session mapping: client's index maps to destination
		sessionKey := fmt.Sprintf("%d:%d", pattern.DestIndex, pattern.ClientIndex)

		// Check if we already have this session
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
		logger.Info("Rebuilt WireGuard session from communication pattern: %s -> %s (packets: %d)",
			sessionKey, pattern.ToDestination.String(), pattern.PacketCount)
	}
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
