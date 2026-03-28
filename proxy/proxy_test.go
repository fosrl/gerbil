package proxy

import (
	"net"
	"testing"

	"github.com/fosrl/gerbil/proxyproto"
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

			result := proxyproto.BuildV1Header(clientTCP, targetTCP)
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

	result := proxyproto.BuildV1Header(clientAddr, targetAddr)
	expected := "PROXY UNKNOWN\r\n"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestBuildProxyProtocolHeaderFromInfo(t *testing.T) {
	// Test IPv4 case
	info := &proxyproto.Info{
		Protocol: "TCP4",
		SrcIP:    "10.0.0.1",
		DestIP:   "192.168.1.100",
		SrcPort:  12345,
		DestPort: 443,
	}

	targetAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	header := proxyproto.BuildV1HeaderFromInfo(info, targetAddr)

	expected := "PROXY TCP4 10.0.0.1 127.0.0.1 12345 8080\r\n"
	if header != expected {
		t.Errorf("Expected header '%s', got '%s'", expected, header)
	}

	// Test IPv6 case
	info = &proxyproto.Info{
		Protocol: "TCP6",
		SrcIP:    "2001:db8::1",
		DestIP:   "2001:db8::2",
		SrcPort:  12345,
		DestPort: 443,
	}

	targetAddr, _ = net.ResolveTCPAddr("tcp6", "[::1]:8080")
	header = proxyproto.BuildV1HeaderFromInfo(info, targetAddr)

	expected = "PROXY TCP6 2001:db8::1 ::1 12345 8080\r\n"
	if header != expected {
		t.Errorf("Expected header '%s', got '%s'", expected, header)
	}
}

func TestParseV2UDPHeader(t *testing.T) {
	// Build a minimal PROXY v2 header for IPv4 UDP
	// Magic (12) + ver/cmd (1) + fam/proto (1) + len (2) + src IP (4) + dst IP (4) + src port (2) + dst port (2) = 28 bytes
	header := []byte{
		// Magic signature
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		// Version 2 (0x2x), PROXY command (0x01)
		0x21,
		// AF_INET (0x1x), DGRAM/UDP (0x02)
		0x12,
		// Address block length: 12 bytes (4+4+2+2)
		0x00, 0x0C,
		// Source IP: 192.168.1.100
		192, 168, 1, 100,
		// Destination IP: 10.0.0.1
		10, 0, 0, 1,
		// Source port: 4500
		0x11, 0x94,
		// Destination port: 21820
		0x55, 0x3C,
	}

	// Append a fake application payload
	payload := []byte{0x01, 0x02, 0x03}
	data := append(header, payload...)

	info, remaining, ok := proxyproto.ParseV2UDPHeader(data)
	if !ok {
		t.Fatal("Expected ParseV2UDPHeader to return ok=true")
	}
	if info == nil {
		t.Fatal("Expected non-nil Info")
	}
	if info.Protocol != "UDP4" {
		t.Errorf("Expected protocol UDP4, got %s", info.Protocol)
	}
	if info.SrcIP != "192.168.1.100" {
		t.Errorf("Expected SrcIP 192.168.1.100, got %s", info.SrcIP)
	}
	if info.DestIP != "10.0.0.1" {
		t.Errorf("Expected DestIP 10.0.0.1, got %s", info.DestIP)
	}
	if info.SrcPort != 4500 {
		t.Errorf("Expected SrcPort 4500, got %d", info.SrcPort)
	}
	if info.DestPort != 21820 {
		t.Errorf("Expected DestPort 21820, got %d", info.DestPort)
	}
	if len(remaining) != len(payload) {
		t.Errorf("Expected %d remaining bytes, got %d", len(payload), len(remaining))
	}
}

func TestParseV2UDPHeaderNoHeader(t *testing.T) {
	// Data that does NOT start with v2 magic should be returned as-is
	data := []byte{0x01, 0x02, 0x03}
	info, remaining, ok := proxyproto.ParseV2UDPHeader(data)
	if ok {
		t.Error("Expected ok=false for non-v2 data")
	}
	if info != nil {
		t.Error("Expected nil Info for non-v2 data")
	}
	if len(remaining) != len(data) {
		t.Errorf("Expected remaining to equal original data length %d, got %d", len(data), len(remaining))
	}
}

func TestIsV2Header(t *testing.T) {
	valid := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		// extra bytes beyond the magic
		0x21, 0x12,
	}
	if !proxyproto.IsV2Header(valid) {
		t.Error("Expected IsV2Header=true for valid magic")
	}

	invalid := []byte{0x01, 0x02, 0x03}
	if proxyproto.IsV2Header(invalid) {
		t.Error("Expected IsV2Header=false for non-magic data")
	}

	tooShort := []byte{0x0D, 0x0A}
	if proxyproto.IsV2Header(tooShort) {
		t.Error("Expected IsV2Header=false for too-short data")
	}
}