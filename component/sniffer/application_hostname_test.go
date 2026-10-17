package sniffer

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestApplicationHostnameDestinationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, observed, sniff string
		role                  C.ApplicationHostnameRole
		mapping               bool
		preserve              bool
	}{
		{name: "disabled", sniff: "sniff.invalid"},
		{name: "matching TLS", observed: "route.invalid", sniff: "route.invalid", role: C.ApplicationHostnameTLS, preserve: true},
		{name: "conflicting TLS", observed: "route.invalid", sniff: "sniff.invalid", role: C.ApplicationHostnameTLS},
		{name: "verified inner", observed: "route.invalid", sniff: "outer.invalid", role: C.ApplicationHostnameECHInner, preserve: true},
		{name: "mapping retains provenance", observed: "route.invalid", sniff: "route.invalid", role: C.ApplicationHostnameTLS, mapping: true, preserve: true},
	} {
		for _, override := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/route-only", true: "/override"}[override], func(t *testing.T) {
				m := &C.Metadata{NetWork: C.TCP, Type: C.REDIR,
					SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 12345,
					DstIP: netip.MustParseAddr("192.0.2.20"), DstPort: 443}
				original := m.DstIP
				if tc.observed != "" {
					if err := m.SetApplicationHostname(tc.observed, tc.role, func() bool { return true }); err != nil {
						t.Fatal(err)
					}
				}
				if tc.mapping {
					m.Host, m.DNSMode = "hint.invalid", C.DNSMapping
				}
				before := m.Clone()
				replaceDomain(m, tc.sniff, override)
				if m.SniffHost != tc.sniff {
					t.Fatal("sniffed result missing")
				}
				if tc.preserve {
					if m.DstIP != original || m.Host != before.Host || m.DNSMode != before.DNSMode || m.RuleHost() != tc.observed {
						t.Fatalf("application destination changed: %+v", m)
					}
				} else if override {
					if m.DstIP.IsValid() || m.Host != tc.sniff || m.RuleHost() != tc.sniff {
						t.Fatal("existing override behavior changed")
					}
				} else if m.DstIP != original || m.RuleHost() != tc.sniff {
					t.Fatal("existing route-only behavior changed")
				}
			})
		}
	}
}
