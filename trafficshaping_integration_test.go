package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTrafficShapingKernel drives the real tc commands against a dummy "wg0" in a throwaway network
// namespace. It needs CAP_NET_ADMIN, so it only runs when GERBIL_TC_INTEGRATION=1, e.g.:
//
//	GERBIL_TC_INTEGRATION=1 unshare -rn go test -run TestTrafficShapingKernel .
func TestTrafficShapingKernel(t *testing.T) {
	if os.Getenv("GERBIL_TC_INTEGRATION") != "1" {
		t.Skip("set GERBIL_TC_INTEGRATION=1 and run in a scratch network namespace")
	}

	oldIface, oldIfb := interfaceName, ifbName
	interfaceName, ifbName = "wg0", "ifb_wg0"
	t.Cleanup(func() {
		interfaceName, ifbName = oldIface, oldIfb
		exec.Command("ip", "link", "del", "wg0").Run()
		exec.Command("ip", "link", "del", "ifb_wg0").Run()
	})

	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	run("ip", "link", "add", "wg0", "type", "dummy")
	run("ip", "link", "set", "wg0", "up")
	// Make sure the ifb module is loaded so ensureIFBDevice doesn't skip ingress shaping.
	run("ip", "link", "add", "ifb_probe", "type", "ifb")
	run("ip", "link", "del", "ifb_probe")

	// Leave junk behind, as an older gerbil would have, to check startup wipes it.
	run("tc", "qdisc", "add", "dev", "wg0", "root", "handle", "1:", "htb", "default", "9999")
	run("tc", "filter", "add", "dev", "wg0", "protocol", "ip", "parent", "1:", "prio", "1",
		"u32", "match", "ip", "dst", "100.89.1.0", "flowid", "1:0")

	if err := initTrafficShaping(); err != nil {
		t.Fatal(err)
	}
	if !ifbReady {
		t.Fatal("IFB not ready")
	}
	if out := run("tc", "filter", "show", "dev", "wg0", "parent", "1:"); strings.Contains(out, "flowid") {
		t.Fatalf("stale filters survived startup:\n%s", out)
	}

	peers := []string{"100.89.0.2/32", "100.89.0.28/32", "100.89.1.28/32", "100.89.2.28/32", "100.89.0.20/32", "100.89.1.0/24"}
	for _, p := range peers {
		if err := setupPeerBandwidthLimit(p, "8mbit"); err != nil {
			t.Fatal(err)
		}
	}

	countFilters := func(dev, parent string) int {
		out := run("tc", "filter", "show", "dev", dev, "parent", parent)
		return strings.Count(out, "flowid")
	}
	if n := countFilters("ifb_wg0", "2:"); n != len(peers) {
		t.Fatalf("ifb filters = %d, want %d", n, len(peers))
	}

	// Churn the peers that used to wipe 100.89.2.28's filter: .2 (prefix match on 2:2x) and the
	// other .28 peers (shared class 2:28). Re-add, update and remove them repeatedly.
	for i := 0; i < 3; i++ {
		for _, p := range []string{"100.89.0.2/32", "100.89.0.28/32", "100.89.1.28/32", "100.89.0.20/32"} {
			if err := removePeerBandwidthLimit(p); err != nil {
				t.Fatal(err)
			}
			if err := setupPeerBandwidthLimit(p, "8mbit"); err != nil {
				t.Fatal(err)
			}
			if err := setupPeerBandwidthLimit(p, "16mbit"); err != nil {
				t.Fatal(err)
			}
		}
		if err := setupPeerBandwidthLimit("100.89.1.0/24", "8mbit"); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"100.89.0.2/32", "100.89.0.28/32", "100.89.1.28/32"} {
		if err := removePeerBandwidthLimit(p); err != nil {
			t.Fatal(err)
		}
	}

	for _, dev := range []struct{ name, parent, match string }{
		{"wg0", "1:", "6459021c"}, {"ifb_wg0", "2:", "6459021c"},
	} {
		out := run("tc", "filter", "show", "dev", dev.name, "parent", dev.parent)
		if !strings.Contains(out, "flowid "+dev.parent+"21c") || !strings.Contains(out, dev.match) {
			t.Fatalf("100.89.2.28 lost its filter on %s:\n%s", dev.name, out)
		}
		// 100.89.0.20 and 100.89.1.0/24 remain alongside 100.89.2.28.
		if n := countFilters(dev.name, dev.parent); n != 3 {
			t.Fatalf("%s has %d filters, want 3:\n%s", dev.name, n, out)
		}
		if strings.Contains(out, "flowid "+dev.parent+" ") {
			t.Fatalf("%s has a filter pointing at the qdisc root:\n%s", dev.name, out)
		}
	}
	if out := run("tc", "class", "show", "dev", "ifb_wg0", "classid", "2:21c"); !strings.Contains(out, "rate 8Mbit") {
		t.Fatalf("class 2:21c missing or wrong rate:\n%s", out)
	}
	if out := run("tc", "class", "show", "dev", "ifb_wg0", "classid", "2:14"); !strings.Contains(out, "rate 16Mbit") {
		t.Fatalf("100.89.0.20 update not applied:\n%s", out)
	}

	// /32 filters must be evaluated before the /24.
	out := run("tc", "filter", "show", "dev", "ifb_wg0", "parent", "2:")
	if strings.Index(out, "pref 1 ") > strings.Index(out, "pref 9 ") {
		t.Fatalf("/24 filter ordered before /32 filters:\n%s", out)
	}
}
