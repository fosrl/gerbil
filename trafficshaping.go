package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/fosrl/gerbil/logger"
	"github.com/vishvananda/netlink"
)

// Per-peer traffic shaping.
//
// Egress (traffic towards a peer) is shaped by an HTB qdisc with handle 1: on the WireGuard
// interface. Ingress (traffic from a peer) is redirected from the WireGuard interface to an IFB
// device and shaped there by an HTB qdisc with handle 2:. Every shaped allowed-IP prefix gets one
// HTB class on each qdisc, both with the same minor number, plus one u32 filter per qdisc that
// steers the prefix's traffic into that class.
//
// Packets that match no filter fall through to the HTB default class, which is deliberately never
// created, so they are sent unshaped. That means any peer whose filter or class goes missing is
// silently unlimited, so class IDs must be unique per prefix and filters must only ever be deleted
// by their exact class ID.

const (
	egressQdiscMajor  = 0x1
	ingressQdiscMajor = 0x2
	// defaultClassMinor is the HTB "default" class. It is never created and must never be handed
	// out to a peer.
	defaultClassMinor = 0x9999
	// maxFilterPref is the pref given to the broadest possible prefix (/0).
	maxFilterPref = 33
)

// shapingLimit is the HTB rate and optional burst applied to a peer. rate is used as both rate and
// ceil. burst is used as both burst and cburst; empty leaves tc to pick its default, which is
// about one packet, so the peer can never exceed rate even briefly.
type shapingLimit struct {
	rate  string
	burst string
}

func (l shapingLimit) String() string {
	if l.burst == "" {
		return l.rate
	}
	return l.rate + " burst " + l.burst
}

// htbArgs returns the tc arguments for an HTB class with this limit.
func (l shapingLimit) htbArgs() []string {
	args := []string{"htb", "rate", l.rate, "ceil", l.rate}
	if l.burst != "" {
		args = append(args, "burst", l.burst, "cburst", l.burst)
	}
	return args
}

// tcRateRegex matches a tc HTB rate/ceil value, e.g. "50mbit", "1gbit", "500kbit".
var tcRateRegex = regexp.MustCompile(`^([0-9]+)(bit|kbit|mbit|gbit|kibit|mibit|gibit)$`)

// tcSizeRegex matches a tc size in bytes, e.g. "4mb", "512kb", "1600". Units follow tc: k/kb is
// 1024 bytes and m/mb is 1024*1024 bytes.
var tcSizeRegex = regexp.MustCompile(`^([0-9]+)(b|k|kb|m|mb)?$`)

const (
	// minBurstBytes keeps a burst from being smaller than one full-size packet.
	minBurstBytes = 1600
	// maxBurstSeconds is how long a burst may take to drain at the class rate. HTB stores the
	// burst as a time in a 32-bit count of 64ns ticks (about 274.9s) and tc refuses anything
	// longer with "burst out of range", which would leave the peer without a class.
	maxBurstSeconds = 270
)

func parseTCRate(s string) (float64, error) {
	m := tcRateRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid rate %q: expected a tc rate such as 8mbit or 1gbit", s)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate %q: %v", s, err)
	}
	mult := map[string]float64{
		"bit": 1, "kbit": 1e3, "mbit": 1e6, "gbit": 1e9,
		"kibit": 1 << 10, "mibit": 1 << 20, "gibit": 1 << 30,
	}[m[2]]
	if n == 0 {
		return 0, fmt.Errorf("invalid rate %q: must be greater than zero", s)
	}
	return n * mult, nil
}

func parseTCSize(s string) (float64, error) {
	m := tcSizeRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid burst %q: expected a size in bytes such as 4mb, 512kb or 1600", s)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid burst %q: %v", s, err)
	}
	mult := map[string]float64{"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "m": 1 << 20, "mb": 1 << 20}[m[2]]
	return n * mult, nil
}

// newShapingLimit validates rate and burst together. An empty burst is allowed and means "use tc's
// default".
func newShapingLimit(rate, burst string) (shapingLimit, error) {
	bitsPerSec, err := parseTCRate(rate)
	if err != nil {
		return shapingLimit{}, err
	}
	if burst != "" {
		bytes, err := parseTCSize(burst)
		if err != nil {
			return shapingLimit{}, err
		}
		if bytes < minBurstBytes {
			return shapingLimit{}, fmt.Errorf("invalid burst %q: must be at least %d bytes", burst, minBurstBytes)
		}
		if secs := bytes * 8 / bitsPerSec; secs > maxBurstSeconds {
			return shapingLimit{}, fmt.Errorf("burst %s is too large for rate %s: it would take %.0fs to drain and tc allows at most %ds",
				burst, rate, secs, maxBurstSeconds)
		}
	}
	return shapingLimit{rate: rate, burst: burst}, nil
}

// resolvePeerShapingLimit applies the global defaults to a peer's optional overrides.
func resolvePeerShapingLimit(rate, burst string) (shapingLimit, error) {
	if rate == "" {
		rate = bandwidthLimit
	}
	if burst == "" {
		burst = bandwidthBurst
	}
	return newShapingLimit(rate, burst)
}

// ifbReady is set once the IFB device and its HTB qdisc are in place. When false, only egress
// shaping is applied.
var ifbReady bool

// shapedPrefix is the shaping state for one allowed-IP prefix.
type shapedPrefix struct {
	minor         uint16
	egressFilter  bool
	ingressFilter bool
}

// classAllocator hands out HTB class minors, one per prefix. Minors are unique across all prefixes
// so that two peers can never end up sharing (or deleting) each other's class or filters.
type classAllocator struct {
	mu       sync.Mutex
	byPrefix map[netip.Prefix]*shapedPrefix
	byMinor  map[uint16]netip.Prefix
}

func newClassAllocator() *classAllocator {
	return &classAllocator{
		byPrefix: make(map[netip.Prefix]*shapedPrefix),
		byMinor:  make(map[uint16]netip.Prefix),
	}
}

var shaper = newClassAllocator()

// preferredMinor returns the minor a prefix should get if it is free: the low 16 bits of its
// address. Within a /16 or smaller WireGuard subnet this is unique per host, and it keeps class IDs
// readable (100.89.2.28 -> 2:21c).
func preferredMinor(p netip.Prefix) uint16 {
	a := p.Addr().As4()
	return uint16(a[2])<<8 | uint16(a[3])
}

func reservedMinor(m uint16) bool {
	return m == 0 || m == defaultClassMinor
}

// allocate returns the shaping state for p, creating it with a free minor if p has none yet. The
// second return value is true when the entry was newly created. Callers must hold a.mu.
func (a *classAllocator) allocate(p netip.Prefix) (*shapedPrefix, bool, error) {
	if entry, ok := a.byPrefix[p]; ok {
		return entry, false, nil
	}
	start := preferredMinor(p)
	for i := 0; i <= 0xffff; i++ {
		m := start + uint16(i) // wraps around
		if reservedMinor(m) {
			continue
		}
		if _, taken := a.byMinor[m]; taken {
			continue
		}
		entry := &shapedPrefix{minor: m}
		a.byPrefix[p] = entry
		a.byMinor[m] = p
		return entry, true, nil
	}
	return nil, false, fmt.Errorf("no free tc class IDs left for %s", p)
}

// release frees p's minor. Callers must hold a.mu.
func (a *classAllocator) release(p netip.Prefix) {
	if entry, ok := a.byPrefix[p]; ok {
		delete(a.byMinor, entry.minor)
		delete(a.byPrefix, p)
	}
}

// reset forgets all allocations. Used at startup together with wiping the kernel tc state.
func (a *classAllocator) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byPrefix = make(map[netip.Prefix]*shapedPrefix)
	a.byMinor = make(map[uint16]netip.Prefix)
}

// normalizeShapingPrefix parses an allowed IP as either a CIDR ("100.89.2.28/32") or a bare
// address (treated as a /32) and returns it masked to its network address. Only IPv4 is supported,
// since the filters match on IPv4 headers.
func normalizeShapingPrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		parsed, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %v", s, err)
		}
		p = parsed
	} else {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address %q: %v", s, err)
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr := p.Addr().Unmap()
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("traffic shaping only supports IPv4, got %s", s)
	}
	bits := p.Bits()
	if bits > 32 { // an IPv4-mapped IPv6 prefix such as ::ffff:1.2.3.4/128
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// filterPref orders filters longest prefix first, mirroring WireGuard's own routing. A peer with a
// /32 must match its own filter before a broader prefix that also covers its address.
func filterPref(p netip.Prefix) int {
	return 1 + (32 - p.Bits())
}

// tcClassID formats a class ID the way tc prints it (hex, no leading zeros), so it can be compared
// directly against "flowid" values in `tc filter show` output.
func tcClassID(major, minor uint16) string {
	return fmt.Sprintf("%x:%x", major, minor)
}

type tcFilterRef struct {
	handle string
	pref   string
}

// parseTCFiltersForFlowID returns the handle and pref of every filter in `tc filter show` output
// whose flowid is exactly flowID. Matching is on the whole token, so "2:2" does not match "2:28".
func parseTCFiltersForFlowID(output, flowID string) []tcFilterRef {
	var refs []tcFilterRef
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		var handle, pref, flow string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "fh":
				handle = fields[i+1]
			case "pref":
				pref = fields[i+1]
			case "flowid":
				flow = fields[i+1]
			}
		}
		if flow == flowID && handle != "" && pref != "" {
			refs = append(refs, tcFilterRef{handle: handle, pref: pref})
		}
	}
	return refs
}

func runTC(args ...string) (string, error) {
	out, err := exec.Command("tc", args...).CombinedOutput()
	return string(out), err
}

func tcNotFound(output string) bool {
	return strings.Contains(output, "No such file or directory") ||
		strings.Contains(output, "Cannot find") ||
		strings.Contains(output, "Cannot delete qdisc with handle of zero") ||
		strings.Contains(output, "Invalid handle")
}

// tcDeleteFilters removes every filter on dev/parent that points at exactly flowID.
func tcDeleteFilters(dev, parent, flowID string) {
	out, err := runTC("filter", "show", "dev", dev, "parent", parent)
	if err != nil {
		logger.Warn("Failed to list tc filters on %s parent %s: %v, output: %s", dev, parent, err, out)
		return
	}
	for _, ref := range parseTCFiltersForFlowID(out, flowID) {
		if delOut, err := runTC("filter", "del", "dev", dev, "parent", parent,
			"handle", ref.handle, "prio", ref.pref, "u32"); err != nil {
			logger.Warn("Failed to delete tc filter %s (pref %s) on %s: %v, output: %s", ref.handle, ref.pref, dev, err, delOut)
		} else {
			logger.Debug("Deleted tc filter %s (pref %s, flowid %s) on %s", ref.handle, ref.pref, flowID, dev)
		}
	}
}

// initTrafficShaping wipes any shaping state left over from a previous gerbil process (whose class
// allocations we no longer know about), then creates the egress HTB qdisc and the IFB device.
// Peers are (re)added afterwards by ensureWireguardPeers.
func initTrafficShaping() error {
	shaper.reset()
	ifbReady = false

	if out, err := runTC("qdisc", "del", "dev", interfaceName, "root"); err != nil && !tcNotFound(out) {
		logger.Warn("Failed to clear root qdisc on %s: %v, output: %s", interfaceName, err, out)
	}
	if _, err := netlink.LinkByName(ifbName); err == nil {
		if out, err := runTC("qdisc", "del", "dev", ifbName, "root"); err != nil && !tcNotFound(out) {
			logger.Warn("Failed to clear root qdisc on %s: %v, output: %s", ifbName, err, out)
		}
	}

	if out, err := runTC("qdisc", "add", "dev", interfaceName, "root", "handle",
		fmt.Sprintf("%x:", egressQdiscMajor), "htb", "default", fmt.Sprintf("%x", defaultClassMinor)); err != nil {
		return fmt.Errorf("failed to add HTB root qdisc to %s: %v, output: %s", interfaceName, err, out)
	}
	logger.Info("Created HTB root qdisc on %s", interfaceName)

	return ensureIFBDevice()
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
	out, err := runTC("qdisc", "show", "dev", interfaceName)
	if err != nil {
		return fmt.Errorf("failed to query qdiscs on %s: %v", interfaceName, err)
	}
	if !strings.Contains(out, "ingress") {
		if out, err := runTC("qdisc", "add", "dev", interfaceName, "handle", "ffff:", "ingress"); err != nil {
			return fmt.Errorf("failed to add ingress qdisc to %s: %v, output: %s", interfaceName, err, out)
		}
		logger.Info("Added ingress qdisc to %s", interfaceName)
	}

	// Add a catch-all filter that redirects every ingress packet from wg0 to the IFB device.
	// Per-peer rate limiting then happens on the IFB device's egress HTB qdisc (handle 2:).
	out, err = runTC("filter", "show", "dev", interfaceName, "parent", "ffff:")
	if err != nil || !strings.Contains(out, ifbName) {
		if out, err := runTC("filter", "add", "dev", interfaceName,
			"parent", "ffff:", "protocol", "ip",
			"u32", "match", "u32", "0", "0",
			"action", "mirred", "egress", "redirect", "dev", ifbName); err != nil {
			return fmt.Errorf("failed to add ingress redirect filter on %s: %v, output: %s", interfaceName, err, out)
		}
		logger.Info("Added ingress redirect filter: %s -> %s", interfaceName, ifbName)
	}

	// Ensure an HTB root qdisc exists on the IFB device (handle 2:) for per-peer shaping
	out, err = runTC("qdisc", "show", "dev", ifbName)
	if err != nil {
		return fmt.Errorf("failed to query qdiscs on %s: %v", ifbName, err)
	}
	if !strings.Contains(out, "htb") {
		if out, err := runTC("qdisc", "add", "dev", ifbName, "root", "handle",
			fmt.Sprintf("%x:", ingressQdiscMajor), "htb", "default", fmt.Sprintf("%x", defaultClassMinor)); err != nil {
			return fmt.Errorf("failed to add HTB qdisc to %s: %v, output: %s", ifbName, err, out)
		}
		logger.Info("Added HTB root qdisc (handle 2:) to IFB device %s", ifbName)
	}

	ifbReady = true
	logger.Info("IFB device %s ready for ingress traffic shaping", ifbName)
	return nil
}

// setupPeerBandwidthLimit limits traffic to and from allowedIP (a CIDR or bare IPv4 address) to
// limit. Calling it again for a prefix that is already shaped only replaces the rate and burst,
// which is how per-peer limits are updated at runtime.
func setupPeerBandwidthLimit(allowedIP string, limit shapingLimit) error {
	p, err := normalizeShapingPrefix(allowedIP)
	if err != nil {
		return err
	}

	shaper.mu.Lock()
	defer shaper.mu.Unlock()

	entry, isNew, err := shaper.allocate(p)
	if err != nil {
		return err
	}
	pref := fmt.Sprintf("%d", filterPref(p))
	match := p.String()

	egressClass := tcClassID(egressQdiscMajor, entry.minor)
	egressParent := fmt.Sprintf("%x:", egressQdiscMajor)
	if out, err := runTC(append([]string{"class", "replace", "dev", interfaceName, "parent", egressParent,
		"classid", egressClass}, limit.htbArgs()...)...); err != nil {
		if isNew {
			shaper.release(p)
		}
		return fmt.Errorf("failed to add/replace class %s for %s: %v, output: %s", egressClass, p, err, out)
	}
	if !entry.egressFilter {
		// Clear anything already pointing at this class before adding ours, so retries
		// don't stack duplicate filters.
		tcDeleteFilters(interfaceName, egressParent, egressClass)
		if out, err := runTC("filter", "add", "dev", interfaceName, "protocol", "ip", "parent", egressParent,
			"prio", pref, "u32", "match", "ip", "dst", match, "flowid", egressClass); err != nil {
			logger.Warn("Failed to add egress filter for %s: %v, output: %s", p, err, out)
		} else {
			entry.egressFilter = true
		}
	}

	ingressClass := tcClassID(ingressQdiscMajor, entry.minor)
	if ifbReady {
		ingressParent := fmt.Sprintf("%x:", ingressQdiscMajor)
		if out, err := runTC(append([]string{"class", "replace", "dev", ifbName, "parent", ingressParent,
			"classid", ingressClass}, limit.htbArgs()...)...); err != nil {
			logger.Warn("Failed to add/replace IFB class %s for %s: %v, output: %s", ingressClass, p, err, out)
		} else if !entry.ingressFilter {
			tcDeleteFilters(ifbName, ingressParent, ingressClass)
			if out, err := runTC("filter", "add", "dev", ifbName, "protocol", "ip", "parent", ingressParent,
				"prio", pref, "u32", "match", "ip", "src", match, "flowid", ingressClass); err != nil {
				logger.Warn("Failed to add IFB ingress filter for %s: %v, output: %s", p, err, out)
			} else {
				entry.ingressFilter = true
			}
		}
	}

	logger.Info("Setup bandwidth limit of %s for %s (egress class %s, ingress class %s)", limit, p, egressClass, ingressClass)
	return nil
}

// removePeerBandwidthLimit removes the class and filters for allowedIP (a CIDR or bare IPv4
// address) and frees its class ID.
func removePeerBandwidthLimit(allowedIP string) error {
	p, err := normalizeShapingPrefix(allowedIP)
	if err != nil {
		return err
	}

	shaper.mu.Lock()
	defer shaper.mu.Unlock()

	entry, ok := shaper.byPrefix[p]
	if !ok {
		logger.Debug("No bandwidth limit set up for %s, nothing to remove", p)
		return nil
	}

	egressClass := tcClassID(egressQdiscMajor, entry.minor)
	egressParent := fmt.Sprintf("%x:", egressQdiscMajor)
	tcDeleteFilters(interfaceName, egressParent, egressClass)
	if out, err := runTC("class", "del", "dev", interfaceName, "classid", egressClass); err != nil && !tcNotFound(out) {
		logger.Warn("Failed to remove egress class %s for %s: %v, output: %s", egressClass, p, err, out)
	}

	ingressClass := tcClassID(ingressQdiscMajor, entry.minor)
	if ifbReady {
		ingressParent := fmt.Sprintf("%x:", ingressQdiscMajor)
		tcDeleteFilters(ifbName, ingressParent, ingressClass)
		if out, err := runTC("class", "del", "dev", ifbName, "classid", ingressClass); err != nil && !tcNotFound(out) {
			logger.Warn("Failed to remove IFB class %s for %s: %v, output: %s", ingressClass, p, err, out)
		}
	}

	shaper.release(p)
	logger.Info("Removed bandwidth limit for %s (egress class %s, ingress class %s)", p, egressClass, ingressClass)
	return nil
}
