//go:build linux && !android

package sing_tun

import (
	"net/netip"
	"testing"

	tun "github.com/metacubex/sing-tun"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestIPv6SourceBypasses(t *testing.T) {
	options := tun.Options{IPRoute2RuleIndex: 9000, IPRoute2TableIndex: 2022,
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}}
	source := *netlink.NewRule()
	source.Priority, source.Table, source.IifName = 9001, 2022, "lo"
	source.Src = options.Inet6Address[0].Masked()
	low := *netlink.NewRule()
	low.Priority, low.Goto, low.IifName = 9000, 9010, "lo"
	low.Table = 0 // kernel dump omits the GOTO action type; re-encode it explicitly
	low.Src = netip.MustParsePrefix("::/1")
	high := low
	high.Src = netip.MustParsePrefix("8000::/1")
	for _, tc := range []struct {
		name   string
		mutate func(*netlink.Rule)
		want   int
	}{
		{"old-order", func(*netlink.Rule) {}, 2},
		{"already-corrected", func(r *netlink.Rule) { r.Priority = 9001 }, 0},
		{"different-owner", func(r *netlink.Rule) { r.Priority = 8999 }, 0},
		{"different-target", func(r *netlink.Rule) { r.Goto = 9020 }, 0},
		{"uid-exclusion", func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(1000, 1000) }, 0},
		{"reinjection", func(r *netlink.Rule) { r.IifName = "Mihomo" }, 0},
		{"destination-exclusion", func(r *netlink.Rule) { r.Dst = netip.MustParsePrefix("2001:db8::/32") }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := low, high
			tc.mutate(&a)
			tc.mutate(&b)
			got := ipv6SourceBypasses(options, []netlink.Rule{a, b, source})
			if len(got) != tc.want {
				t.Fatalf("selected %d bypasses, want %d", len(got), tc.want)
			}
			for _, rule := range got {
				if rule.Type != unix.FR_ACT_GOTO || rule.Table != -1 {
					t.Fatal("GOTO action lost while round-tripping kernel rules")
				}
			}
		})
	}
	// Neither an unrelated table nor a different prefix licenses a correction.
	for _, other := range []tun.Options{
		{IPRoute2RuleIndex: 9000, IPRoute2TableIndex: 2023, Inet6Address: options.Inet6Address},
		{IPRoute2RuleIndex: 9000, IPRoute2TableIndex: 2022, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}},
	} {
		if got := ipv6SourceBypasses(other, []netlink.Rule{low, high, source}); len(got) != 0 {
			t.Fatal("selected bypasses without this TUN's source lookup")
		}
	}
}
