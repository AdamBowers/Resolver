package securityfilter

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainTree_Matching(t *testing.T) {
	tree := NewDomainTree()
	rules := []string{
		"example.com",      // apex + subdomains
		"*.corp.internal.", // subdomains only
		"=strict.only.net", // apex only
	}
	for _, r := range rules {
		if err := tree.Insert(r); err != nil {
			t.Fatalf("unexpected error inserting %q: %v", r, err)
		}
	}

	tests := []struct {
		qname string
		want  bool
	}{
		// Apex + wildcard rule ("example.com")
		{"example.com.", true},
		{"EXAMPLE.COM", true},
		{"*.example.com.", true},
		{"deep.sub.example.com.", true},
		{"badexample.com.", false},

		// Subdomain-only wildcard ("*.corp.internal.")
		{"corp.internal.", false},
		{"auth.corp.internal.", true},
		{"v1.auth.corp.internal.", true},

		// Exact-only rule ("=strict.only.net")
		{"strict.only.net.", true},
		{"sub.strict.only.net.", false},

		// Unlisted & edge cases
		{"evil.org.", false},
		{".", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := tree.Match(tc.qname); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.qname, got, tc.want)
		}
	}
}

func TestDomainTree_RootWildcard(t *testing.T) {
	tree := NewDomainTree()
	if err := tree.Insert("."); err != nil {
		t.Fatalf("insert root wildcard: %v", err)
	}
	if !tree.Match("anything.example.org.") {
		t.Fatal("expected root wildcard '.' to allow any domain")
	}
}

func TestIPRadixTree_Matching(t *testing.T) {
	tree := NewIPRadixTree()
	entries := []string{
		"192.0.2.0/24",
		"198.51.100.42",
		"2001:db8:dead::/48",
		"2606:4700:4700::1111/128",
	}
	for _, e := range entries {
		if err := tree.InsertString(e); err != nil {
			t.Fatalf("unexpected error inserting %q: %v", e, err)
		}
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"192.0.2.0", true},
		{"192.0.2.255", true},
		{"192.0.3.1", false},
		{"198.51.100.42", true},
		{"198.51.100.43", false},
		// IPv4-mapped IPv6 bypass protection
		{"::ffff:192.0.2.15", true},
		{"::ffff:8.8.8.8", false},
		// IPv6 prefixes & /128 host entries
		{"2001:db8:dead:beef::1", true},
		{"2001:db8:cafe::1", false},
		{"2606:4700:4700::1111", true},
		{"2606:4700:4700::1001", false},
	}

	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.ip)
		if got := tree.Contains(addr); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIPRadixTree_ZeroPrefix(t *testing.T) {
	tree := NewIPRadixTree()
	if err := tree.InsertString("0.0.0.0/0"); err != nil {
		t.Fatalf("insert 0.0.0.0/0: %v", err)
	}
	if !tree.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("expected 0.0.0.0/0 to match any IPv4 address")
	}
	if tree.Contains(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("expected 0.0.0.0/0 not to match IPv6 addresses")
	}
}

var (
	benchTLDs = []string{
		"com.au", "gov.au", "net.au", "org.au", "au",
		"com", "net", "org", "io", "dev", "cloud",
		"internal", "test", "arpa", "co.uk", "nz",
	}
	benchSubLabels = []string{
		"api", "v1", "v2", "auth", "cdn", "edge", "gw",
		"internal", "svc", "metrics", "otel", "proxy", "node",
	}
)

// randomCase randomly uppercases ASCII letters to prevent branch-predictor/hot-path bias
// and exercise the stack lowercasing loop on every benchmark iteration.
func randomCase(rng *rand.Rand, s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' && rng.IntN(2) == 1 {
			c -= 'a' - 'A'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// buildMatchingQName constructs a valid mixed-case FQDN guaranteed to match the inserted rule.
func buildMatchingQName(rng *rand.Rand, rule string) string {
	var qname string
	switch {
	case strings.HasPrefix(rule, "="):
		// Exact apex match only
		qname = strings.TrimPrefix(rule, "=") + "."
	case strings.HasPrefix(rule, "*."):
		// Must have at least 1..3 subdomain labels
		base := strings.TrimPrefix(rule, "*.")
		depth := 1 + rng.IntN(3)
		parts := make([]string, 0, depth+1)
		for range depth {
			parts = append(parts, benchSubLabels[rng.IntN(len(benchSubLabels))])
		}
		parts = append(parts, base)
		qname = strings.Join(parts, ".") + "."
	default:
		// Apex (depth 0) OR 1..3 random subdomain labels
		depth := rng.IntN(4)
		parts := make([]string, 0, depth+1)
		for range depth {
			parts = append(parts, benchSubLabels[rng.IntN(len(benchSubLabels))])
		}
		parts = append(parts, rule)
		qname = strings.Join(parts, ".") + "."
	}

	return randomCase(rng, qname)
}

func BenchmarkDomainTree_Match(b *testing.B) {
	rng := rand.New(rand.NewPCG(42, 1337))
	tree := NewDomainTree()

	const numRules = 10_000
	rules := make([]string, numRules)
	for i := range numRules {
		tld := benchTLDs[rng.IntN(len(benchTLDs))]
		// Mix 2-label ("tenant-42.com") and 3-label ("://tenant-42.com.au") base domains
		var domain string
		if rng.IntN(2) == 0 {
			domain = fmt.Sprintf("tenant-%d.%s", i, tld)
		} else {
			domain = fmt.Sprintf("app-%d.tenant-%d.%s", rng.IntN(20), i, tld)
		}

		var rule string
		switch i % 3 {
		case 0:
			rule = domain
		case 1:
			rule = "*." + domain
		case 2:
			rule = "=" + domain
		}

		rules[i] = rule
		if err := tree.Insert(rule); err != nil {
			b.Fatalf("insert %q: %v", rule, err)
		}
	}

	// Pre-generate 4,096 randomized mixed-case FQDNs spanning all TLDs, depths, and rule modes
	const queryPoolSize = 4096
	queries := make([]string, queryPoolSize)
	for i := range queryPoolSize {
		rule := rules[rng.IntN(numRules)]
		queries[i] = buildMatchingQName(rng, rule)
	}

	b.ReportAllocs()
	idx := 0
	for b.Loop() {
		q := queries[idx&(queryPoolSize-1)]
		idx++
		if !tree.Match(q) {
			b.Fatalf("expected match for %q", q)
		}
	}
}

func BenchmarkIPRadixTree_Contains(b *testing.B) {
	tree := NewIPRadixTree()
	for i := 0; i < 10000; i++ {
		_ = tree.InsertString(fmt.Sprintf("10.%d.%d.0/24", (i>>8)&0xff, i&0xff))
	}
	addr := netip.MustParseAddr("10.21.42.99")

	b.ReportAllocs()
	for b.Loop() {
		if !tree.Contains(addr) {
			b.Fatal("expected match")
		}
	}
}

func FuzzDomainTree(f *testing.F) {
	f.Add("example.com", "://example.com.")
	f.Add("*.corp.internal", "auth.corp.internal.")
	f.Add("=strict.net", "sub.strict.net.")
	f.Add(".", "anything.org.")
	f.Add("...", "")
	f.Add("a..b", "a..b.")

	f.Fuzz(func(t *testing.T, rule string, qname string) {
		tree := NewDomainTree()
		err := tree.Insert(rule)
		got := tree.Match(qname)

		// Invariant: if rule insertion failed, an empty tree must never match anything
		if err != nil && got {
			t.Fatalf("empty tree after failed Insert(%q) unexpectedly matched %q", rule, qname)
		}
	})
}

func FuzzIPRadixTree_Oracle(f *testing.F) {
	f.Add("192.0.2.0/24", "192.0.2.42")
	f.Add("0.0.0.0/0", "8.8.8.8")
	f.Add("2001:db8::/32", "2001:db8:dead::1")
	f.Add("::ffff:10.0.0.0/104", "10.1.2.3")
	f.Add("invalid-cidr", "1.1.1.1")

	f.Fuzz(func(t *testing.T, rawPrefix string, rawIP string) {
		tree := NewIPRadixTree()
		err := tree.InsertString(rawPrefix)

		addr, addrErr := netip.ParseAddr(rawIP)
		if addrErr != nil {
			// Invalid IP must always return false
			if tree.Contains(netip.Addr{}) {
				t.Fatal("invalid netip.Addr matched")
			}
			return
		}

		got := tree.Contains(addr)
		if err != nil {
			if got {
				t.Fatalf("empty tree after failed InsertString(%q) matched %q", rawPrefix, rawIP)
			}
			return
		}

		// Differential oracle: compare against stdlib netip.Prefix.Contains
		var want bool
		if pfx, pfxErr := netip.ParsePrefix(rawPrefix); pfxErr == nil {
			unmappedAddr := addr.Unmap()
			unmappedPfxAddr := pfx.Addr().Unmap()
			bits := pfx.Bits()
			if pfx.Addr().Is4In6() && bits >= 96 {
				bits -= 96
			}
			canonPfx := netip.PrefixFrom(unmappedPfxAddr, bits).Masked()
			want = canonPfx.Contains(unmappedAddr)
		} else if ruleAddr, rErr := netip.ParseAddr(rawPrefix); rErr == nil {
			want = ruleAddr.Unmap() == addr.Unmap()
		}

		if got != want {
			t.Fatalf("mismatch for rule=%q ip=%q: tree.Contains=%v, stdlib=%v", rawPrefix, rawIP, got, want)
		}
	})
}
