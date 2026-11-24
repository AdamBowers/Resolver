package securityfilter

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// PolicySnapshot is an immutable, lock-free read-only snapshot of active blocklist rules
// and stream metadata, swapped atomically via atomic.Pointer[PolicySnapshot].
type PolicySnapshot struct {
	// BlockedDomains holds pre-resolution blocked domain names and wildcard suffixes.
	// Nil when no domain blocklist rules are active (pass-through).
	BlockedDomains *DomainTree

	// BlockedIPs holds post-resolution blocked IPv4/IPv6 CIDR prefixes.
	// Nil when no IP/CIDR blocklist rules are active (pass-through).
	BlockedIPs *IPRadixTree

	BlockedDomainCount uint64
	BlockedCIDRCount   uint64

	PolicyRevision  uint64
	PolicyCreatedAt time.Time
	BundleSequence  uint64
	BundleSignedAt  time.Time
	BundleSHA256    string
	LoadedAt        time.Time
}

// =============================================================================
// 1. Reverse-Label Domain Suffix Tree (Zero-Allocation Hot Path)
// =============================================================================

type matchMode uint8

const (
	matchNone      matchMode = 0
	matchExact     matchMode = 1 << iota // matches this node itself (e.g., "=example.com")
	matchSubdomain                       // matches descendants below this node (e.g., "*.example.com")
)

type domainNode struct {
	children map[string]*domainNode
	mode     matchMode
}

// DomainTree is an immutable reverse-label suffix trie for fast domain allowlisting.
// Lookup scans labels right-to-left using stack buffers so Match() performs 0 heap allocations.
type DomainTree struct {
	root  domainNode
	count int
}

// NewDomainTree constructs an empty DomainTree.
func NewDomainTree() *DomainTree {
	return &DomainTree{}
}

// Count returns the number of rules inserted into the tree.
func (t *DomainTree) Count() int {
	if t == nil {
		return 0
	}
	return t.count
}

// Insert adds a domain rule to the tree (call only during tree construction before publishing).
// Supported formats:
//   - "."            : match all domains
//   - "example.com"  : match example.com and all subdomains (*.example.com)
//   - "*.example.com": match subdomains of example.com only (not apex example.com)
//   - "=example.com" : match apex example.com only (no subdomains)
func (t *DomainTree) Insert(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("empty domain rule")
	}

	if s == "." {
		t.root.mode |= matchSubdomain
		t.count++
		return nil
	}

	exactOnly := false
	wildcardOnly := false

	switch {
	case strings.HasPrefix(s, "="):
		exactOnly = true
		s = strings.TrimSpace(s[1:])
	case strings.HasPrefix(s, "*."):
		wildcardOnly = true
		s = strings.TrimSpace(s[2:])
	}

	// Normalize trailing dot and lowercase
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n/*=") {
		return fmt.Errorf("invalid domain rule %q", raw)
	}

	labels := strings.Split(s, ".")
	curr := &t.root
	for i := len(labels) - 1; i >= 0; i-- {
		lbl := labels[i]
		if lbl == "" || len(lbl) > 63 {
			return fmt.Errorf("invalid DNS label %q in rule %q", lbl, raw)
		}
		if curr.children == nil {
			curr.children = make(map[string]*domainNode, 1)
		}
		next, ok := curr.children[lbl]
		if !ok {
			next = &domainNode{}
			curr.children[lbl] = next
		}
		curr = next
	}

	switch {
	case exactOnly:
		curr.mode |= matchExact
	case wildcardOnly:
		curr.mode |= matchSubdomain
	default:
		curr.mode |= matchExact | matchSubdomain
	}

	t.count++
	return nil
}

// Match returns true if qname is permitted by the allowlist tree.
// Executes in O(labels) with 0 heap allocations.
func (t *DomainTree) Match(qname string) bool {
	if t == nil {
		return false
	}

	// Strip trailing root dot(s)
	end := len(qname)
	for end > 0 && qname[end-1] == '.' {
		end--
	}
	if end == 0 {
		return t.root.mode&matchExact != 0
	}
	if t.root.mode&matchSubdomain != 0 {
		return true
	}

	// Stack buffer for lowercasing single DNS labels (max RFC 1035 label length is 63 bytes)
	var labelBuf [63]byte
	curr := &t.root

	// Walk labels right-to-left without allocating slices or strings
	for end > 0 {
		start := end - 1
		for start >= 0 && qname[start] != '.' {
			start--
		}
		lblStart := start + 1
		lblLen := end - lblStart
		if lblLen == 0 || lblLen > len(labelBuf) {
			return false
		}

		for i := 0; i < lblLen; i++ {
			c := qname[lblStart+i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			labelBuf[i] = c
		}

		if curr.children == nil {
			return false
		}
		// Go compiler optimizes map[string] lookup with string(buf[:n]) to 0 heap allocs
		next, ok := curr.children[string(labelBuf[:lblLen])]
		if !ok {
			return false
		}

		isFirstLabel := start < 0
		if isFirstLabel {
			return next.mode&matchExact != 0
		}
		if next.mode&matchSubdomain != 0 {
			return true
		}

		curr = next
		end = start
	}

	return false
}

// =============================================================================
// 2. Binary CIDR Radix Tree (IPv4 32-bit & IPv6 128-bit, Zero-Allocation)
// =============================================================================

type ipNode struct {
	children [2]*ipNode
	blocked  bool
}

// IPRadixTree is an immutable bitwise prefix trie for post-resolution IP denylisting.
type IPRadixTree struct {
	v4Root *ipNode
	v6Root *ipNode
	count  int
}

// NewIPRadixTree constructs an empty IPRadixTree.
func NewIPRadixTree() *IPRadixTree {
	return &IPRadixTree{}
}

// Count returns the number of CIDR/IP prefixes inserted into the tree.
func (t *IPRadixTree) Count() int {
	if t == nil {
		return 0
	}
	return t.count
}

// InsertPrefix adds a canonical netip.Prefix (e.g., 203.0.113.0/24 or 2001:db8::/32).
func (t *IPRadixTree) InsertPrefix(pfx netip.Prefix) error {
	if !pfx.IsValid() {
		return fmt.Errorf("invalid IP prefix")
	}

	// Canonicalize prefix (mask host bits) and unmap IPv4-in-IPv6 prefixes
	addr := pfx.Addr().Unmap()
	bits := pfx.Bits()
	if pfx.Addr().Is4In6() && bits >= 96 {
		bits -= 96
	}
	pfx = netip.PrefixFrom(addr, bits).Masked()

	if addr.Is4() {
		b := addr.As4()
		if t.v4Root == nil {
			t.v4Root = &ipNode{}
		}
		insertBits(t.v4Root, b[:], pfx.Bits())
	} else {
		b := addr.As16()
		if t.v6Root == nil {
			t.v6Root = &ipNode{}
		}
		insertBits(t.v6Root, b[:], pfx.Bits())
	}

	t.count++
	return nil
}

// InsertString parses a CIDR ("198.51.100.0/24") or single IP ("198.51.100.5") and inserts it.
func (t *IPRadixTree) InsertString(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("empty IP/CIDR entry")
	}

	if strings.ContainsRune(s, '/') {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		return t.InsertPrefix(pfx)
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP address %q: %w", raw, err)
	}
	addr = addr.Unmap()
	return t.InsertPrefix(netip.PrefixFrom(addr, addr.BitLen()))
}

func insertBits(root *ipNode, octets []byte, prefixLen int) {
	curr := root
	for i := 0; i < prefixLen; i++ {
		if curr.blocked {
			// A broader covering CIDR already blocks this entire subtree
			return
		}
		bit := (octets[i>>3] >> (7 - (i & 7))) & 1
		if curr.children[bit] == nil {
			curr.children[bit] = &ipNode{}
		}
		curr = curr.children[bit]
	}
	curr.blocked = true
	// Prune narrower child branches now subsumed by this broader prefix
	curr.children[0] = nil
	curr.children[1] = nil
}

// Contains returns true if addr matches any blocked IP or CIDR prefix in the tree.
// Unmaps IPv4-mapped IPv6 addresses automatically and performs 0 heap allocations.
func (t *IPRadixTree) Contains(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}

	addr = addr.Unmap()
	if addr.Is4() {
		if t.v4Root == nil {
			return false
		}
		b := addr.As4()
		return matchBits(t.v4Root, b[:], 32)
	}

	if t.v6Root == nil {
		return false
	}
	b := addr.As16()
	return matchBits(t.v6Root, b[:], 128)
}

func matchBits(root *ipNode, octets []byte, maxBits int) bool {
	curr := root
	for i := 0; i < maxBits; i++ {
		if curr.blocked {
			return true
		}
		bit := (octets[i>>3] >> (7 - (i & 7))) & 1
		curr = curr.children[bit]
		if curr == nil {
			return false
		}
	}
	return curr.blocked
}
