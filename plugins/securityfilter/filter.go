package securityfilter

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type SecurityFilter struct {
	Next    plugin.Handler
	loader  *PolicyLoader
	control *ControlServer
}

func (s *SecurityFilter) Name() string { return "securityfilter" }

func (s *SecurityFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	snap := s.loader.Current()
	if snap.BlockedDomains != nil {
		for _, q := range r.Question {
			if snap.BlockedDomains.Match(q.Name) {
				// Emit CEF log & return NXDOMAIN / REFUSED immediately without upstream recursion
			}
		}

	}
	return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
}
