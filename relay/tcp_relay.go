package relay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fosrl/gerbil/logger"
)

type TCPRelayRegistrationMessage struct {
	Type              string `json:"type"`
	OlmID             string `json:"olmId"`
	NewtID            string `json:"newtId"`
	Token             string `json:"token"`
	PublicKey         string `json:"publicKey"`
	ReachableAt       string `json:"reachableAt"`
	ExitNodePublicKey string `json:"exitNodePublicKey"`
}

func isTCPRelayRegistrationType(t string) bool {
	return t == "relay-register" || t == "tcp-relay-register"
}

// TCPProxyServer accepts framed packets over TCP and forwards them through the
// same relay logic/path used by UDP.
type TCPProxyServer struct {
	addr     string
	udpProxy *UDPProxyServer
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc

	connections sync.Map // map[string]*DestinationConn where key is destination "ip:port-clientKey"
}

func NewTCPProxyServer(parentCtx context.Context, addr string, udpProxy *UDPProxyServer) *TCPProxyServer {
	ctx, cancel := context.WithCancel(parentCtx)
	return &TCPProxyServer{
		addr:     addr,
		udpProxy: udpProxy,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *TCPProxyServer) Start() error {
	if s.udpProxy == nil {
		return fmt.Errorf("udp proxy is required")
	}

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = listener
	logger.Info("TCP relay listening on %s", s.addr)

	go s.acceptLoop()
	go s.cleanupIdleConnections()

	return nil
}

func (s *TCPProxyServer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.connections.Range(func(key, value interface{}) bool {
		if dc, ok := value.(*DestinationConn); ok && dc.conn != nil {
			_ = dc.conn.Close()
		}
		return true
	})
}

func (s *TCPProxyServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				logger.Error("TCP relay accept error: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *TCPProxyServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Debug("TCP connection from %s", remoteAddr)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		packet, err := readFramedPacket(conn)
		if err != nil {
			logger.Debug("TCP relay connection closed: %s (%v)", remoteAddr, err)
			return
		}

		logger.Debug("TCP connection from %s, processing packet (len=%d)", remoteAddr, len(packet))
		if err := s.processPacket(packet, remoteAddr, func(data []byte) error {
			return writeFramedPacket(conn, data)
		}); err != nil {
			logger.Debug("TCP relay packet processing failed for %s: %v", remoteAddr, err)
		}
	}
}

func (s *TCPProxyServer) processPacket(packet []byte, clientKey string, writeResponse func([]byte) error) error {
	if len(packet) == 0 {
		return nil
	}

	if packet[0] >= 1 && packet[0] <= 4 {
		s.handleWireGuardPacketTCP(packet, clientKey, writeResponse)
		return nil
	}

	// Relay tunnel registration packets are plain JSON and allow the server to
	// create a proxy mapping for this TCP connection before WireGuard handshakes.
	var registration TCPRelayRegistrationMessage
	if err := json.Unmarshal(packet, &registration); err == nil &&
		isTCPRelayRegistrationType(registration.Type) &&
		registration.Token != "" &&
		(registration.OlmID != "" || registration.NewtID != "") {
		return s.handleRegistration(registration, clientKey)
	}
	if err := json.Unmarshal(packet, &registration); err == nil &&
		isTCPRelayRegistrationType(registration.Type) {
		logger.Warn(
			"Rejected TCP relay registration from %s: missing required fields (token=%t olmId=%t newtId=%t)",
			clientKey,
			registration.Token != "",
			registration.OlmID != "",
			registration.NewtID != "",
		)
	}

	var encMsg EncryptedHolePunchMessage
	if err := json.Unmarshal(packet, &encMsg); err != nil {
		return fmt.Errorf("unmarshal encrypted hole punch: %w", err)
	}
	if encMsg.EphemeralPublicKey == "" {
		return fmt.Errorf("malformed encrypted hole punch without ephemeral key")
	}

	decryptedData, err := s.udpProxy.decryptMessage(encMsg)
	if err != nil {
		return fmt.Errorf("decrypt hole punch: %w", err)
	}

	var msg HolePunchMessage
	if err := json.Unmarshal(decryptedData, &msg); err != nil {
		return fmt.Errorf("unmarshal hole punch message: %w", err)
	}

	host, port, err := net.SplitHostPort(clientKey)
	if err != nil {
		return fmt.Errorf("split client address: %w", err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("parse client port: %w", err)
	}

	endpoint := ClientEndpoint{
		NewtID:            msg.NewtID,
		OlmID:             msg.OlmID,
		Token:             msg.Token,
		IP:                host,
		Port:              portInt,
		Timestamp:         time.Now().Unix(),
		ReachableAt:       s.udpProxy.ReachableAt,
		ExitNodePublicKey: s.udpProxy.privateKey.PublicKey().String(),
		ClientPublicKey:   msg.PublicKey,
	}

	logger.Debug("Created endpoint from TCP client %s: IP=%s, Port=%d", clientKey, endpoint.IP, endpoint.Port)
	s.udpProxy.notifyServer(endpoint)
	s.udpProxy.clearSessionsForIP(endpoint.IP)
	return nil
}

func (s *TCPProxyServer) handleRegistration(registration TCPRelayRegistrationMessage, clientKey string) error {
	host, port, err := net.SplitHostPort(clientKey)
	if err != nil {
		return fmt.Errorf("split client address: %w", err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("parse client port: %w", err)
	}

	endpoint := ClientEndpoint{
		OlmID:             registration.OlmID,
		NewtID:            registration.NewtID,
		Token:             registration.Token,
		IP:                host,
		Port:              portInt,
		Timestamp:         time.Now().Unix(),
		ReachableAt:       registration.ReachableAt,
		ExitNodePublicKey: registration.ExitNodePublicKey,
		ClientPublicKey:   registration.PublicKey,
	}

	logger.Info(
		"Registered TCP relay client %s for olmId=%s newtId=%s",
		clientKey,
		registration.OlmID,
		registration.NewtID,
	)

	s.udpProxy.notifyServer(endpoint)
	s.udpProxy.clearSessionsForIP(endpoint.IP)
	return nil
}

func (s *TCPProxyServer) handleWireGuardPacketTCP(packet []byte, clientKey string, writeResponse func([]byte) error) {
	if len(packet) == 0 {
		logger.Error("Received empty TCP WireGuard packet")
		return
	}

	messageType := packet[0]
	receiverIndex, senderIndex, ok := extractWireGuardIndices(packet)
	if !ok {
		logger.Error("Failed to extract WireGuard indices from TCP packet")
		return
	}

	mappingObj, ok := s.udpProxy.proxyMappings.Load(clientKey)
	if !ok {
		logger.Debug("TCP relay: no proxy mapping for %s", clientKey)
		return
	}

	proxyMapping := mappingObj.(ProxyMapping)
	logger.Debug(
		"TCP relay: found proxy mapping for %s with %d destinations",
		clientKey,
		len(proxyMapping.Destinations),
	)
	proxyMapping.LastUsed = time.Now()
	s.udpProxy.proxyMappings.Store(clientKey, proxyMapping)

	switch messageType {
	case WireGuardMessageTypeHandshakeInitiation:
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve TCP relay destination: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, clientKey, writeResponse)
			if err != nil {
				logger.Error("Failed to create TCP relay UDP connection: %v", err)
				continue
			}

			if _, err = conn.Write(packet); err != nil {
				logger.Debug("Failed to forward TCP relay handshake initiation: %v", err)
			}
		}

	case WireGuardMessageTypeHandshakeResponse:
		sessionKey := fmt.Sprintf("%d:%d", receiverIndex, senderIndex)
		clientAddr, _ := net.ResolveUDPAddr("udp", clientKey)
		s.udpProxy.wgSessions.Store(sessionKey, &WireGuardSession{
			ReceiverIndex: receiverIndex,
			SenderIndex:   senderIndex,
			DestAddr:      clientAddr,
			LastSeen:      time.Now(),
		})

		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve TCP relay destination: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, clientKey, writeResponse)
			if err != nil {
				logger.Error("Failed to create TCP relay UDP connection: %v", err)
				continue
			}

			if _, err = conn.Write(packet); err != nil {
				logger.Error("Failed to forward TCP relay handshake response: %v", err)
			}
		}

	default:
		for _, dest := range proxyMapping.Destinations {
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dest.DestinationIP, dest.DestinationPort))
			if err != nil {
				logger.Error("Failed to resolve TCP relay destination: %v", err)
				continue
			}

			conn, err := s.getOrCreateConnection(destAddr, clientKey, writeResponse)
			if err != nil {
				logger.Error("Failed to create TCP relay UDP connection: %v", err)
				continue
			}

			if _, err = conn.Write(packet); err != nil {
				logger.Debug("Failed to forward TCP relay packet: %v", err)
			}
		}
	}
}

func (s *TCPProxyServer) getOrCreateConnection(destAddr *net.UDPAddr, clientKey string, writeResponse func([]byte) error) (*net.UDPConn, error) {
	key := destAddr.String() + "-" + clientKey
	if conn, ok := s.connections.Load(key); ok {
		destConn := conn.(*DestinationConn)
		destConn.lastUsed = time.Now()
		return destConn.conn, nil
	}

	newConn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	s.connections.Store(key, &DestinationConn{
		conn:     newConn,
		lastUsed: time.Now(),
	})

	go s.handleResponses(newConn, key, writeResponse)
	return newConn, nil
}

func (s *TCPProxyServer) handleResponses(conn *net.UDPConn, connectionKey string, writeResponse func([]byte) error) {
	buffer := make([]byte, 1500)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			logger.Debug("TCP relay downstream read error on %s: %v", connectionKey, err)
			return
		}

		if err := writeResponse(buffer[:n]); err != nil {
			logger.Debug("TCP relay write response failed on %s: %v", connectionKey, err)
			return
		}
	}
}

func (s *TCPProxyServer) cleanupIdleConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.connections.Range(func(key, value interface{}) bool {
				destConn := value.(*DestinationConn)
				if now.Sub(destConn.lastUsed) > 10*time.Minute {
					_ = destConn.conn.Close()
					s.connections.Delete(key)
				}
				return true
			})
		case <-s.ctx.Done():
			return
		}
	}
}

func readFramedPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := ioReadFull(conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > 64*1024 {
		return nil, fmt.Errorf("invalid frame length %d", length)
	}
	packet := make([]byte, length)
	if _, err := ioReadFull(conn, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func writeFramedPacket(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
