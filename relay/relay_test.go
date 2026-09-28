package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestRelayForwardsIPv6Peer checks that a mapping registered for an IPv6
// client (as /update-destinations and the hole-punch path do) is found when
// that client's WireGuard packets arrive, and that the packet reaches an IPv6
// destination.
func TestRelayForwardsIPv6Peer(t *testing.T) {
	dest, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	defer dest.Close()

	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewUDPProxyServer(ctx, "[::1]:0", "http://127.0.0.1:0", key, "")
	if err := s.Start(); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	defer s.Stop()

	clientAddr := client.LocalAddr().(*net.UDPAddr)
	destAddr := dest.LocalAddr().(*net.UDPAddr)
	s.UpdateProxyMapping(clientAddr.IP.String(), clientAddr.Port, []PeerDestination{
		{DestinationIP: destAddr.IP.String(), DestinationPort: destAddr.Port},
	})

	// Minimal WireGuard handshake initiation: type 1, sender index 7.
	initiation := make([]byte, 148)
	initiation[0] = WireGuardMessageTypeHandshakeInitiation
	initiation[4] = 7
	if _, err := client.WriteToUDP(initiation, s.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send initiation: %v", err)
	}

	if err := dest.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := dest.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("destination did not receive the forwarded initiation: %v", err)
	}
	if n != len(initiation) || buf[0] != WireGuardMessageTypeHandshakeInitiation {
		t.Fatalf("destination got %d bytes (type %d), want %d bytes of type 1", n, buf[0], len(initiation))
	}
}
