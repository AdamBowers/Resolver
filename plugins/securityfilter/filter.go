package securityfilter

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type SecurityFilter struct {
	Next plugin.Handler
}

func (s *SecurityFilter) Name() string { return PluginName }

func (s *SecurityFilter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
}
