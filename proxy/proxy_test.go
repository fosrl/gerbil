package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestBuildProxyProtocolHeader(t *testing.T) {
	tests := []struct {
		name       string
		clientAddr string
		targetAddr string
		expected   string
	}{
		{
			name:       "IPv4 client and target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "10.0.0.1:443",
			expected:   "PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv6 client and target",
			clientAddr: "[2001:db8::1]:12345",
			targetAddr: "[2001:db8::2]:443",
			expected:   "PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n",
		},
		{
			name:       "IPv4 client with IPv6 loopback target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "[::1]:443",
			expected:   "PROXY TCP4 192.168.1.100 127.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv4 client with IPv6 target",
			clientAddr: "192.168.1.100:12345",
			targetAddr: "[2001:db8::2]:443",
			expected:   "PROXY TCP4 192.168.1.100 127.0.0.1 12345 443\r\n",
		},
		{
			name:       "IPv6 client with IPv4 target",
			clientAddr: "[2001:db8::1]:12345",
			targetAddr: "10.0.0.1:443",
			expected:   "PROXY TCP6 2001:db8::1 ::ffff:10.0.0.1 12345 443\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientTCP, err := net.ResolveTCPAddr("tcp", tt.clientAddr)
			if err != nil {
				t.Fatalf("Failed to resolve client address: %v", err)
			}

			targetTCP, err := net.ResolveTCPAddr("tcp", tt.targetAddr)
			if err != nil {
				t.Fatalf("Failed to resolve target address: %v", err)
			}

			result := buildProxyProtocolHeader(clientTCP, targetTCP)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestBuildProxyProtocolHeaderUnknownType(t *testing.T) {
	// Test with non-TCP address type
	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	targetAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	result := buildProxyProtocolHeader(clientAddr, targetAddr)
	expected := "PROXY UNKNOWN\r\n"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestBuildProxyProtocolHeaderFromInfo(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	// Test IPv4 case
	proxyInfo := &ProxyProtocolInfo{
		Protocol: "TCP4",
		SrcIP:    "10.0.0.1",
		DestIP:   "192.168.1.100",
		SrcPort:  12345,
		DestPort: 443,
	}

	targetAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	header := proxy.buildProxyProtocolHeaderFromInfo(proxyInfo, targetAddr)

	expected := "PROXY TCP4 10.0.0.1 127.0.0.1 12345 8080\r\n"
	if header != expected {
		t.Errorf("Expected header '%s', got '%s'", expected, header)
	}

	// Test IPv6 case
	proxyInfo = &ProxyProtocolInfo{
		Protocol: "TCP6",
		SrcIP:    "2001:db8::1",
		DestIP:   "2001:db8::2",
		SrcPort:  12345,
		DestPort: 443,
	}

	targetAddr, _ = net.ResolveTCPAddr("tcp6", "[::1]:8080")
	header = proxy.buildProxyProtocolHeaderFromInfo(proxyInfo, targetAddr)

	expected = "PROXY TCP6 2001:db8::1 ::1 12345 8080\r\n"
	if header != expected {
		t.Errorf("Expected header '%s', got '%s'", expected, header)
	}
}

// TestParseProxyProtocolHeaderUnknownPreservesPayload checks that when a
// trusted upstream sends "PROXY UNKNOWN\r\n" the bytes that follow the header
// (the TLS ClientHello) are still readable from the returned connection.
func TestParseProxyProtocolHeaderUnknownPreservesPayload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, false, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	payload := []byte("\x16\x03\x01client-hello-bytes")
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
			accepted <- nil
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	// Header and payload arrive in a single segment, as they do when the
	// upstream writes both before the first flush.
	if _, err := client.Write(append([]byte("PROXY UNKNOWN\r\n"), payload...)); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	serverConn := <-accepted
	if serverConn == nil {
		t.FailNow()
	}
	defer serverConn.Close()

	proxyInfo, wrapped, err := proxy.parseProxyProtocolHeader(serverConn)
	if err != nil {
		t.Fatalf("parseProxyProtocolHeader returned error: %v", err)
	}
	if proxyInfo != nil {
		t.Fatalf("Expected nil proxyInfo for PROXY UNKNOWN, got %+v", proxyInfo)
	}

	if err := wrapped.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("Failed to set read deadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("Payload after PROXY UNKNOWN header was lost: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Expected payload %q, got %q", payload, got)
	}
}
