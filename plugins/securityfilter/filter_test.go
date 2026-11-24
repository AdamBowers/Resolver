package securityfilter

import "testing"

func TestPluginName(t *testing.T) {
	s := SecurityFilter{}
	if s.Name() != "securityfilter" {
		t.Fatalf("expected plugin name %q, got %q", "securityfilter", s.Name())
	}
}
