package main

import (
	"net/netip"
	"testing"
)

func TestNormalizeShapingPrefix(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "100.89.2.28", want: "100.89.2.28/32"},
		{in: "100.89.2.28/32", want: "100.89.2.28/32"},
		{in: "100.89.1.5/24", want: "100.89.1.0/24"},
		{in: "0.0.0.0/0", want: "0.0.0.0/0"},
		{in: "::ffff:100.89.2.28/128", want: "100.89.2.28/32"},
		{in: "fd00::1/128", wantErr: true},
		{in: "not-an-ip", wantErr: true},
	}
	for _, c := range cases {
		got, err := normalizeShapingPrefix(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeShapingPrefix(%q) = %s, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeShapingPrefix(%q) error: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("normalizeShapingPrefix(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestFilterPrefLongestPrefixFirst(t *testing.T) {
	host := netip.MustParsePrefix("100.89.1.5/32")
	subnet := netip.MustParsePrefix("100.89.1.0/24")
	if filterPref(host) != 1 {
		t.Errorf("/32 pref = %d, want 1", filterPref(host))
	}
	if filterPref(host) >= filterPref(subnet) {
		t.Errorf("/32 pref %d must sort before /24 pref %d", filterPref(host), filterPref(subnet))
	}
	if got := filterPref(netip.MustParsePrefix("0.0.0.0/0")); got != maxFilterPref {
		t.Errorf("/0 pref = %d, want %d", got, maxFilterPref)
	}
}

func TestAllocatorUniqueAcrossSubnets(t *testing.T) {
	a := newClassAllocator()
	// These all ended in .28 and used to share class 2:28.
	prefixes := []string{"100.89.0.28/32", "100.89.1.28/32", "100.89.2.28/32"}
	seen := map[uint16]string{}
	for _, s := range prefixes {
		e, isNew, err := a.allocate(netip.MustParsePrefix(s))
		if err != nil || !isNew {
			t.Fatalf("allocate(%s) = %v, %v, %v", s, e, isNew, err)
		}
		if other, dup := seen[e.minor]; dup {
			t.Fatalf("%s and %s share minor %x", s, other, e.minor)
		}
		seen[e.minor] = s
	}
	if got := tcClassID(ingressQdiscMajor, a.byPrefix[netip.MustParsePrefix("100.89.2.28/32")].minor); got != "2:21c" {
		t.Errorf("class for 100.89.2.28 = %s, want 2:21c", got)
	}
}

func TestAllocatorSkipsReservedMinors(t *testing.T) {
	a := newClassAllocator()
	// x.x.0.0 would be minor 0 (the qdisc root); x.x.153.153 would be 0x9999 (the htb default).
	for _, s := range []string{"100.89.0.0/24", "10.0.153.153/32"} {
		e, _, err := a.allocate(netip.MustParsePrefix(s))
		if err != nil {
			t.Fatal(err)
		}
		if reservedMinor(e.minor) {
			t.Errorf("%s got reserved minor %x", s, e.minor)
		}
	}
}

func TestAllocatorCollisionProbesAndReuses(t *testing.T) {
	a := newClassAllocator()
	p1 := netip.MustParsePrefix("100.89.2.28/32")
	p2 := netip.MustParsePrefix("100.90.2.28/32") // same low 16 bits, different /16
	e1, _, _ := a.allocate(p1)
	e2, _, _ := a.allocate(p2)
	if e1.minor == e2.minor {
		t.Fatalf("colliding prefixes got the same minor %x", e1.minor)
	}

	again, isNew, _ := a.allocate(p1)
	if isNew || again.minor != e1.minor {
		t.Errorf("re-allocating %s should reuse minor %x, got %x (new=%v)", p1, e1.minor, again.minor, isNew)
	}

	a.release(p1)
	if _, ok := a.byMinor[e1.minor]; ok {
		t.Errorf("minor %x still taken after release", e1.minor)
	}
	if _, ok := a.byMinor[e2.minor]; !ok {
		t.Errorf("releasing %s freed %s's minor", p1, p2)
	}
}

func TestParseTCFiltersExactFlowID(t *testing.T) {
	out := `filter protocol ip pref 1 u32 chain 0
filter protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1
filter protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 2:2 not_in_hw
  match 64590002/ffffffff at 12
filter protocol ip pref 1 u32 chain 0 fh 800::801 order 2049 key ht 800 bkt 0 flowid 2:28 not_in_hw
  match 6459001c/ffffffff at 12
filter protocol ip pref 1 u32 chain 0 fh 800::802 order 2050 key ht 800 bkt 0 flowid 2:21c not_in_hw
  match 6459021c/ffffffff at 12
filter protocol ip pref 1 u32 chain 0 fh 800::803 order 2051 key ht 800 bkt 0 flowid 2: not_in_hw
  match 64590100/ffffffff at 12
filter protocol ip pref 9 u32 chain 0 fh 801::800 order 2048 key ht 801 bkt 0 flowid 2:2 not_in_hw
  match 64590200/ffffff00 at 12
`
	got := parseTCFiltersForFlowID(out, "2:2")
	want := []tcFilterRef{{handle: "800::800", pref: "1"}, {handle: "801::800", pref: "9"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	if got := parseTCFiltersForFlowID(out, "2:21c"); len(got) != 1 || got[0].handle != "800::802" {
		t.Errorf("flowid 2:21c: got %v", got)
	}
	if got := parseTCFiltersForFlowID(out, "2:0"); len(got) != 0 {
		t.Errorf("flowid 2:0 should match nothing, got %v", got)
	}
}
