package securityfilter

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const PluginName = "securityfilter"

func init() {
	plugin.Register(PluginName, setup)
}

func setup(c *caddy.Controller) error {
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &SecurityFilter{Next: next}
	})
	return nil
}
