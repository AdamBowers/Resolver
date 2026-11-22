package securityfilter

import "testing"

func TestPluginName(t *testing.T) {
	if PluginName != "securityfilter" {
		t.Fatalf("expected plugin name %q, got %q", "securityfilter", PluginName)
	}
}
