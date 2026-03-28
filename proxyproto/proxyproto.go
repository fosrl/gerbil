// Package proxyproto provides shared PROXY protocol v1 (TCP) and v2 (UDP) parsing
// and header building utilities used by both the SNI proxy and UDP relay components.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/fosrl/gerbil/logger"
)

// v2Signature is the 12-byte magic prefix for PROXY protocol v2 headers.
var v2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

// Info holds information parsed from an incoming PROXY protocol header (v1 or v2).
type Info struct {
	Protocol string // e.g. "TCP4", "TCP6", "UDP4", "UDP6"
	SrcIP    string
	DestIP   string
	SrcPort  int
	DestPort int
}

// Conn wraps a net.Conn so that reads are satisfied from a pre-pended buffered
// reader first (remaining bytes after PROXY header parsing) and then from the
// underlying connection. All other net.Conn methods are forwarded unchanged.
type Conn struct {
	net.Conn
	Reader io.Reader
}

// Read satisfies net.Conn, draining the buffered reader before falling through
// to the underlying connection.
func (c *Conn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

// IsV2Header returns true when data begins with the 12-byte PROXY protocol v2
// magic signature.
func IsV2Header(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	return bytes.Equal(data[:12], v2Signature)
}

// ParseV2UDPHeader tries to parse a PROXY protocol v2 header from the front of
// a UDP datagram payload.
//
// Three return values are provided:
//   - *Info  – filled when a PROXY command header was parsed successfully; nil
//     for a LOCAL command or unrecognised address family.
//   - []byte – the remaining payload that follows the header (the actual
//     application data).
//   - bool   – true when a v2 header was detected (and consumed), false when
//     no v2 magic is present and data should be treated as-is.
func ParseV2UDPHeader(data []byte) (*Info, []byte, bool) {
	if !IsV2Header(data) {
		return nil, data, false
	}

	// Minimum fixed header size: 12 (magic) + 1 (ver/cmd) + 1 (fam/proto) + 2 (len) = 16
	if len(data) < 16 {
		return nil, data, false
	}

	// Byte 12: version (high nibble) + command (low nibble)
	versionCmd := data[12]
	version := (versionCmd >> 4) & 0x0F
	command := versionCmd & 0x0F

	if version != 2 {
		return nil, data, false
	}

	// Byte 13: address family (high nibble) + transport protocol (low nibble)
	familyProto := data[13]
	family := (familyProto >> 4) & 0x0F
	protocol := familyProto & 0x0F

	// Bytes 14-15: length of the address block that follows, big-endian
	addrLen := int(binary.BigEndian.Uint16(data[14:16]))
	totalHeaderLen := 16 + addrLen

	if len(data) < totalHeaderLen {
		// Truncated packet – signal that a header was detected but is malformed
		return nil, data, false
	}

	payload := data[totalHeaderLen:]

	// LOCAL command (0) carries no address information.
	if command == 0 {
		return nil, payload, true
	}

	if command != 1 {
		// Unknown command – consume the header and return no info
		return nil, payload, true
	}

	addrBlock := data[16:totalHeaderLen]

	var (
		srcIP, destIP net.IP
		srcPort       uint16
		destPort      uint16
		protocolStr   string
	)

	switch {
	case family == 1 && protocol == 1: // AF_INET / STREAM  (TCP over IPv4)
		if len(addrBlock) < 12 {
			return nil, payload, false
		}
		srcIP = net.IP(addrBlock[0:4])
		destIP = net.IP(addrBlock[4:8])
		srcPort = binary.BigEndian.Uint16(addrBlock[8:10])
		destPort = binary.BigEndian.Uint16(addrBlock[10:12])
		protocolStr = "TCP4"

	case family == 1 && protocol == 2: // AF_INET / DGRAM   (UDP over IPv4)
		if len(addrBlock) < 12 {
			return nil, payload, false
		}
		srcIP = net.IP(addrBlock[0:4])
		destIP = net.IP(addrBlock[4:8])
		srcPort = binary.BigEndian.Uint16(addrBlock[8:10])
		destPort = binary.BigEndian.Uint16(addrBlock[10:12])
		protocolStr = "UDP4"

	case family == 2 && protocol == 1: // AF_INET6 / STREAM (TCP over IPv6)
		if len(addrBlock) < 36 {
			return nil, payload, false
		}
		srcIP = net.IP(addrBlock[0:16])
		destIP = net.IP(addrBlock[16:32])
		srcPort = binary.BigEndian.Uint16(addrBlock[32:34])
		destPort = binary.BigEndian.Uint16(addrBlock[34:36])
		protocolStr = "TCP6"

	case family == 2 && protocol == 2: // AF_INET6 / DGRAM  (UDP over IPv6)
		if len(addrBlock) < 36 {
			return nil, payload, false
		}
		srcIP = net.IP(addrBlock[0:16])
		destIP = net.IP(addrBlock[16:32])
		srcPort = binary.BigEndian.Uint16(addrBlock[32:34])
		destPort = binary.BigEndian.Uint16(addrBlock[34:36])
		protocolStr = "UDP6"

	default:
		// UNSPEC or AF_UNIX – consume the header, no address info available
		return nil, payload, true
	}

	info := &Info{
		Protocol: protocolStr,
		SrcIP:    srcIP.String(),
		DestIP:   destIP.String(),
		SrcPort:  int(srcPort),
		DestPort: int(destPort),
	}
	return info, payload, true
}

// ParseV1Header attempts to parse a PROXY protocol v1 (text) header from the
// given TCP connection.
//
// The function first checks whether the remote address appears in
// trustedUpstreams. If it does not, it returns (nil, conn, nil) and the caller
// should treat the connection as a plain (non-proxied) connection.
//
// When a trusted upstream is detected the function reads up to 512 bytes,
// locates the CRLF-terminated header line, and parses the proxy information.
// Whatever bytes were consumed (including any data beyond the header line) are
// re-prepended via a *Conn wrapper so that subsequent reads by the caller are
// transparent.
//
// Return values:
//   - *Info    – non-nil when a valid PROXY header was parsed.
//   - net.Conn – always a valid connection (possibly a *Conn wrapper).
//   - error    – non-nil only on hard failures (e.g. bad port numbers).
func ParseV1Header(conn net.Conn, trustedUpstreams map[string]struct{}) (*Info, net.Conn, error) {
	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, conn, fmt.Errorf("failed to parse remote address: %w", err)
	}

	if _, isTrusted := trustedUpstreams[remoteHost]; !isTrusted {
		return nil, conn, nil
	}

	// Give the upstream 5 s to deliver the PROXY header before timing out.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, conn, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// The PROXY v1 spec mandates the header fits in 108 bytes; 512 is generous.
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		logger.Debug("Could not read from trusted upstream %s, treating as regular connection: %v", remoteHost, err)
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			logger.Debug("Failed to clear read deadline: %v", clearErr)
		}
		return nil, conn, nil
	}

	// Locate the CRLF that terminates the PROXY header line.
	headerEnd := bytes.Index(buffer[:n], []byte("\r\n"))
	if headerEnd == -1 {
		logger.Debug("No PROXY protocol header from trusted upstream %s, treating as regular TLS connection", remoteHost)
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			logger.Debug("Failed to clear read deadline: %v", clearErr)
		}
		newReader := io.MultiReader(bytes.NewReader(buffer[:n]), conn)
		return nil, &Conn{Conn: conn, Reader: newReader}, nil
	}

	headerLine := string(buffer[:headerEnd])
	remainingData := buffer[headerEnd+2 : n]

	parts := strings.Fields(headerLine)

	// Handle "PROXY UNKNOWN" – upstream knows the real source but we don't need it.
	if len(parts) == 2 && parts[0] == "PROXY" && parts[1] == "UNKNOWN" {
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			logger.Debug("Failed to clear read deadline: %v", clearErr)
		}
		var newConn net.Conn
		if len(remainingData) > 0 {
			newConn = &Conn{Conn: conn, Reader: io.MultiReader(bytes.NewReader(remainingData), conn)}
		} else {
			newConn = conn
		}
		return nil, newConn, nil
	}

	if len(parts) != 6 || parts[0] != "PROXY" {
		// Malformed line from a trusted upstream – re-prepend everything and
		// let the caller deal with it as a plain TLS connection.
		logger.Debug("Invalid PROXY protocol from trusted upstream %s, treating as regular TLS connection: %s", remoteHost, headerLine)
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			logger.Debug("Failed to clear read deadline: %v", clearErr)
		}
		newReader := io.MultiReader(bytes.NewReader(buffer[:n]), conn)
		return nil, &Conn{Conn: conn, Reader: newReader}, nil
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

	// Re-assemble a reader that returns any bytes read beyond the header first.
	var newReader io.Reader
	if len(remainingData) > 0 {
		newReader = io.MultiReader(bytes.NewReader(remainingData), conn)
	} else {
		newReader = conn
	}
	wrappedConn := &Conn{Conn: conn, Reader: newReader}

	if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
		return nil, conn, fmt.Errorf("failed to clear read deadline: %w", clearErr)
	}

	info := &Info{
		Protocol: protocol,
		SrcIP:    srcIP,
		DestIP:   destIP,
		SrcPort:  srcPort,
		DestPort: destPort,
	}
	return info, wrappedConn, nil
}

// BuildV1Header constructs a PROXY protocol v1 header string from two TCP
// addresses, normalising the protocol family so that v1's constraint of a
// single family per header is satisfied.
func BuildV1Header(clientAddr, targetAddr net.Addr) string {
	clientTCP, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return "PROXY UNKNOWN\r\n"
	}
	targetTCP, ok := targetAddr.(*net.TCPAddr)
	if !ok {
		return "PROXY UNKNOWN\r\n"
	}

	var protocol, targetIP string

	if clientTCP.IP.To4() != nil {
		// IPv4 client
		protocol = "TCP4"
		if targetTCP.IP.To4() != nil {
			targetIP = targetTCP.IP.String()
		} else if targetTCP.IP.IsLoopback() {
			targetIP = "127.0.0.1"
		} else {
			targetIP = "127.0.0.1" // safe fallback for mixed-family
		}
	} else {
		// IPv6 client
		protocol = "TCP6"
		if targetTCP.IP.To4() != nil {
			targetIP = "::ffff:" + targetTCP.IP.String()
		} else {
			targetIP = targetTCP.IP.String()
		}
	}

	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		protocol, clientTCP.IP.String(), targetIP, clientTCP.Port, targetTCP.Port)
}

// BuildV1HeaderFromInfo constructs a PROXY protocol v1 header string using a
// previously-parsed *Info (i.e. when this server itself sits behind an
// upstream proxy) and the target TCP address.
func BuildV1HeaderFromInfo(info *Info, targetAddr net.Addr) string {
	targetTCP, ok := targetAddr.(*net.TCPAddr)
	if !ok {
		return "PROXY UNKNOWN\r\n"
	}

	srcIP := net.ParseIP(info.SrcIP)
	if srcIP == nil {
		return "PROXY UNKNOWN\r\n"
	}

	var protocol, targetIP string

	if srcIP.To4() != nil {
		protocol = "TCP4"
		if targetTCP.IP.To4() != nil {
			targetIP = targetTCP.IP.String()
		} else if targetTCP.IP.IsLoopback() {
			targetIP = "127.0.0.1"
		} else {
			targetIP = "127.0.0.1"
		}
	} else {
		protocol = "TCP6"
		if targetTCP.IP.To4() != nil {
			targetIP = "::ffff:" + targetTCP.IP.String()
		} else {
			targetIP = targetTCP.IP.String()
		}
	}

	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		protocol, info.SrcIP, targetIP, info.SrcPort, targetTCP.Port)
}