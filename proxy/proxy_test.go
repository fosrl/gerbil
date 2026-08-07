package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
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

func TestPeekClientHelloExtractsSNIAndPreservesData(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	clientHello := captureClientHelloRecord(t, "example.com")
	stream := append(append([]byte(nil), clientHello...), []byte("remaining bytes")...)

	hostname, reader, err := proxy.peekClientHello(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("peekClientHello returned error: %v", err)
	}
	if hostname != "example.com" {
		t.Fatalf("Expected hostname example.com, got %q", hostname)
	}

	forwarded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed reading forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, stream) {
		t.Fatalf("Forwarded stream did not match original input")
	}
}

func TestPeekClientHelloHandlesFragmentedHandshakeRecords(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	clientHello := captureClientHelloRecord(t, "fragmented.example.com")
	fragmented := fragmentHandshakeRecord(t, clientHello, 37)

	hostname, reader, err := proxy.peekClientHello(bytes.NewReader(fragmented))
	if err != nil {
		t.Fatalf("peekClientHello returned error for fragmented handshake: %v", err)
	}
	if hostname != "fragmented.example.com" {
		t.Fatalf("Expected fragmented.example.com, got %q", hostname)
	}

	forwarded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed reading fragmented forwarded stream: %v", err)
	}
	if !bytes.Equal(forwarded, fragmented) {
		t.Fatalf("Forwarded fragmented stream did not match original input")
	}
}

func TestPeekClientHelloWithoutSNI(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	clientHello := captureClientHelloRecord(t, "")
	_, _, err = proxy.peekClientHello(bytes.NewReader(clientHello))
	if err == nil {
		t.Fatal("Expected missing SNI error, got nil")
	}
	if !strings.Contains(err.Error(), "SNI extension not present") {
		t.Fatalf("Expected missing SNI error, got %v", err)
	}
}

func TestPeekClientHelloNormalizesHostname(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	clientHello := captureClientHelloRecord(t, "ExAmPle.Com.")
	hostname, reader, err := proxy.peekClientHello(bytes.NewReader(clientHello))
	if err != nil {
		t.Fatalf("peekClientHello returned error: %v", err)
	}
	if hostname != "example.com" {
		t.Fatalf("Expected canonical hostname example.com, got %q", hostname)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatalf("Failed to drain forwarded reader: %v", err)
	}
}

func TestParseClientHelloServerNameRejectsTrailingData(t *testing.T) {
	record := captureClientHelloRecord(t, "example.com")
	clientHello := extractClientHelloPayload(t, record)
	malformed := append(append([]byte(nil), clientHello...), 0x00)

	_, err := parseClientHelloServerName(malformed)
	if err == nil {
		t.Fatal("Expected parse error for trailing ClientHello data, got nil")
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("Expected trailing data parse error, got %v", err)
	}
}

func TestParseClientHelloServerNameAllowsAdditionalNameEntries(t *testing.T) {
	record := captureClientHelloRecord(t, "example.com")
	clientHello := extractClientHelloPayload(t, record)
	withExtraName := addUnknownServerNameEntryToClientHello(t, clientHello)

	got, err := parseClientHelloServerName(withExtraName)
	if err != nil {
		t.Fatalf("Expected parser to accept additional name entries, got error: %v", err)
	}
	if got != "example.com" {
		t.Fatalf("Expected hostname example.com, got %q", got)
	}
}

func TestPeekClientHelloMatchesOldBehavior(t *testing.T) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		t.Fatalf("Failed to create SNI proxy: %v", err)
	}

	testCases := []struct {
		name       string
		serverName string
	}{
		{name: "basic", serverName: "example.com"},
		{name: "mixed_case", serverName: "ExAmPle.Com"},
		{name: "trailing_dot", serverName: "example.com."},
		{name: "single_label", serverName: "localhost"},
		{name: "long_hostname", serverName: "very.long.subdomain.name.for.sni.benchmark.example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := captureClientHelloRecord(t, tc.serverName)
			assertNewAndOldPeekMatch(t, proxy, input)

			fragmented := fragmentHandshakeRecord(t, input, 37)
			assertNewAndOldPeekMatch(t, proxy, fragmented)
		})
	}
}

func assertNewAndOldPeekMatch(tb testing.TB, proxy *SNIProxy, input []byte) {
	tb.Helper()

	newHost, newReader, newErr := proxy.peekClientHello(bytes.NewReader(input))
	oldHost, oldReader, oldErr := oldPeekClientHello(bytes.NewReader(input))

	if (newErr != nil) != (oldErr != nil) {
		tb.Fatalf("error mismatch: newErr=%v oldErr=%v", newErr, oldErr)
	}
	if newErr != nil && oldErr != nil {
		return
	}

	// New path normalizes hostnames; compare with same normalization to check behavioral parity.
	oldHost = strings.TrimSuffix(strings.ToLower(oldHost), ".")
	if newHost != oldHost {
		tb.Fatalf("hostname mismatch: new=%q old=%q", newHost, oldHost)
	}

	newForwarded, err := io.ReadAll(newReader)
	if err != nil {
		tb.Fatalf("failed to read new forwarded stream: %v", err)
	}
	oldForwarded, err := io.ReadAll(oldReader)
	if err != nil {
		tb.Fatalf("failed to read old forwarded stream: %v", err)
	}

	if !bytes.Equal(newForwarded, oldForwarded) {
		tb.Fatalf("forwarded stream mismatch between new and old parsers")
	}
}

func captureClientHelloRecord(tb testing.TB, serverName string) []byte {
	tb.Helper()

	clientConn, serverConn := net.Pipe()
	errCh := make(chan error, 1)

	go func() {
		cfg := &tls.Config{InsecureSkipVerify: true}
		if serverName != "" {
			cfg.ServerName = serverName
		}
		errCh <- tls.Client(clientConn, cfg).Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		tb.Fatalf("Failed to set read deadline: %v", err)
	}

	var header [5]byte
	if _, err := io.ReadFull(serverConn, header[:]); err != nil {
		tb.Fatalf("Failed to read TLS record header: %v", err)
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	record := make([]byte, 5+recordLen)
	copy(record[:5], header[:])
	if _, err := io.ReadFull(serverConn, record[5:]); err != nil {
		tb.Fatalf("Failed to read TLS record payload: %v", err)
	}

	_ = clientConn.Close()
	_ = serverConn.Close()
	<-errCh

	return record
}

func extractClientHelloPayload(tb testing.TB, record []byte) []byte {
	tb.Helper()

	if len(record) < 9 {
		tb.Fatalf("TLS record too short for ClientHello: %d", len(record))
	}
	if record[0] != tlsRecordTypeHandshake {
		tb.Fatalf("Expected handshake record type %d, got %d", tlsRecordTypeHandshake, record[0])
	}

	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) != 5+recordLen {
		tb.Fatalf("Invalid record length: header=%d bytes, total=%d bytes", recordLen, len(record))
	}

	payload := record[5:]
	if payload[0] != tlsHandshakeTypeClientHello {
		tb.Fatalf("Expected ClientHello handshake type %d, got %d", tlsHandshakeTypeClientHello, payload[0])
	}

	clientHelloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+clientHelloLen {
		tb.Fatalf("ClientHello payload truncated: expected=%d actual=%d", clientHelloLen, len(payload)-4)
	}

	return append([]byte(nil), payload[4:4+clientHelloLen]...)
}

func fragmentHandshakeRecord(tb testing.TB, record []byte, firstPayloadLen int) []byte {
	tb.Helper()

	if len(record) < 6 {
		tb.Fatalf("TLS record too short: %d", len(record))
	}

	payload := record[5:]
	if firstPayloadLen <= 0 || firstPayloadLen >= len(payload) {
		tb.Fatalf("Invalid fragment length %d for payload length %d", firstPayloadLen, len(payload))
	}

	version := record[1:3]
	first := make([]byte, 5+firstPayloadLen)
	first[0] = tlsRecordTypeHandshake
	copy(first[1:3], version)
	binary.BigEndian.PutUint16(first[3:5], uint16(firstPayloadLen))
	copy(first[5:], payload[:firstPayloadLen])

	remainingLen := len(payload) - firstPayloadLen
	second := make([]byte, 5+remainingLen)
	second[0] = tlsRecordTypeHandshake
	copy(second[1:3], version)
	binary.BigEndian.PutUint16(second[3:5], uint16(remainingLen))
	copy(second[5:], payload[firstPayloadLen:])

	return append(first, second...)
}

func addUnknownServerNameEntryToClientHello(tb testing.TB, clientHello []byte) []byte {
	tb.Helper()

	out := append([]byte(nil), clientHello...)
	if len(out) < 39 {
		tb.Fatalf("ClientHello too short: %d", len(out))
	}

	offset := 0
	offset += 2  // legacy version
	offset += 32 // random

	sessionIDLen := int(out[offset])
	offset++
	offset += sessionIDLen
	if offset+2 > len(out) {
		tb.Fatal("Invalid ClientHello while reading cipher suites length")
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(out[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset >= len(out) {
		tb.Fatal("Invalid ClientHello while reading compression methods length")
	}

	compressionMethodsLen := int(out[offset])
	offset++
	offset += compressionMethodsLen
	if offset+2 > len(out) {
		tb.Fatal("Invalid ClientHello while reading extensions length")
	}

	extensionsLenOffset := offset
	extensionsLen := int(binary.BigEndian.Uint16(out[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(out) {
		tb.Fatal("Invalid ClientHello: extensions overflow payload")
	}

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(out[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(out[offset+2 : offset+4]))
		extDataOffset := offset + 4
		extDataEnd := extDataOffset + extDataLen
		if extDataEnd > extensionsEnd {
			tb.Fatal("Invalid extension length in ClientHello")
		}

		if extType == 0 {
			if extDataLen < 2 {
				tb.Fatal("Invalid server_name extension")
			}
			serverNameListLen := int(binary.BigEndian.Uint16(out[extDataOffset : extDataOffset+2]))
			serverNameListOffset := extDataOffset + 2
			serverNameListEnd := serverNameListOffset + serverNameListLen
			if serverNameListEnd > extDataEnd {
				tb.Fatal("Invalid server_name list length")
			}

			// Add a non-host_name entry (type 1) to verify parser tolerates additional names.
			extraEntry := []byte{1, 0, 1, 0}
			out = append(out[:serverNameListEnd], append(extraEntry, out[serverNameListEnd:]...)...)

			binary.BigEndian.PutUint16(out[extDataOffset:extDataOffset+2], uint16(serverNameListLen+len(extraEntry)))
			binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(extDataLen+len(extraEntry)))
			binary.BigEndian.PutUint16(out[extensionsLenOffset:extensionsLenOffset+2], uint16(extensionsLen+len(extraEntry)))
			return out
		}

		offset = extDataEnd
	}

	tb.Fatal("server_name extension not found")
	return nil
}

func BenchmarkSNIExtraction(b *testing.B) {
	proxy, err := NewSNIProxy(8443, "", "", "127.0.0.1", 443, nil, true, nil)
	if err != nil {
		b.Fatalf("Failed to create SNI proxy: %v", err)
	}

	fixtures := []struct {
		name       string
		serverName string
	}{
		{name: "short", serverName: "a.io"},
		{name: "typical", serverName: "bench.example.com"},
		{name: "mixed_case", serverName: "Bench.Example.Com"},
		{name: "long", serverName: "very.long.subdomain.name.for.sni.benchmark.example.com"},
	}

	for _, fixture := range fixtures {
		clientHello := captureClientHelloRecord(b, fixture.serverName)
		fragmented := fragmentHandshakeRecord(b, clientHello, 37)

		benchmarks := []struct {
			name  string
			input []byte
			fn    func(*testing.B, *SNIProxy, []byte)
		}{
			{name: "new/direct_parser", input: clientHello, fn: benchmarkNewPeekClientHello},
			{name: "old/tls_handshake", input: clientHello, fn: benchmarkOldPeekClientHello},
			{name: "new/direct_parser_fragmented", input: fragmented, fn: benchmarkNewPeekClientHello},
			{name: "old/tls_handshake_fragmented", input: fragmented, fn: benchmarkOldPeekClientHello},
		}

		for _, bm := range benchmarks {
			b.Run(fixture.name+"/"+bm.name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(bm.input)))
				bm.fn(b, proxy, bm.input)
			})
		}
	}
}

func benchmarkNewPeekClientHello(b *testing.B, proxy *SNIProxy, input []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname, reader, err := proxy.peekClientHello(bytes.NewReader(input))
		if err != nil {
			b.Fatalf("peekClientHello returned error: %v", err)
		}
		if hostname == "" {
			b.Fatal("peekClientHello returned empty hostname")
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatalf("Failed to drain reader: %v", err)
		}
	}
}

func benchmarkOldPeekClientHello(b *testing.B, _ *SNIProxy, input []byte) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname, reader, err := oldPeekClientHello(bytes.NewReader(input))
		if err != nil {
			b.Fatalf("oldPeekClientHello returned error: %v", err)
		}
		if hostname == "" {
			b.Fatal("oldPeekClientHello returned empty hostname")
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatalf("Failed to drain reader: %v", err)
		}
	}
}

func oldPeekClientHello(reader io.Reader) (string, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := oldReadClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return "", nil, err
	}
	return hello.ServerName, io.MultiReader(peekedBytes, reader), nil
}

func oldReadClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(benchmarkReadOnlyConn{reader: reader}, &tls.Config{
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

type benchmarkReadOnlyConn struct {
	reader io.Reader
}

func (conn benchmarkReadOnlyConn) Read(p []byte) (int, error)       { return conn.reader.Read(p) }
func (conn benchmarkReadOnlyConn) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (conn benchmarkReadOnlyConn) Close() error                     { return nil }
func (conn benchmarkReadOnlyConn) LocalAddr() net.Addr              { return benchmarkStaticAddr("local") }
func (conn benchmarkReadOnlyConn) RemoteAddr() net.Addr             { return benchmarkStaticAddr("remote") }
func (conn benchmarkReadOnlyConn) SetDeadline(time.Time) error      { return nil }
func (conn benchmarkReadOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (conn benchmarkReadOnlyConn) SetWriteDeadline(time.Time) error { return nil }

type benchmarkStaticAddr string

func (a benchmarkStaticAddr) Network() string { return "tcp" }
func (a benchmarkStaticAddr) String() string  { return string(a) }
