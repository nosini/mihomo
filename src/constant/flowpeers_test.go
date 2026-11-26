package constant

import (
	"net/netip"
	"testing"
)

func TestMetadataFlowPeers(t *testing.T) {
	packetDst := netip.MustParseAddrPort("1.1.1.1:443")
	inIP := netip.MustParseAddr("::ffff:127.0.0.1")
	inExpected := netip.MustParseAddrPort("127.0.0.1:7890")

	for _, tc := range []struct {
		name string
		typ  Type
		want []netip.AddrPort
	}{
		{"TUN", TUN, []netip.AddrPort{packetDst}},
		{"TPROXY", TPROXY, []netip.AddrPort{packetDst}},
		{"REDIR", REDIR, []netip.AddrPort{inExpected}},
		{"HTTP", HTTP, []netip.AddrPort{inExpected}},
		{"HTTPS", HTTPS, []netip.AddrPort{inExpected}},
		{"SOCKS4", SOCKS4, []netip.AddrPort{inExpected}},
		{"SOCKS5", SOCKS5, []netip.AddrPort{inExpected}},
		{"TUNNEL", TUNNEL, []netip.AddrPort{inExpected}},
		{"SHADOWSOCKS", SHADOWSOCKS, []netip.AddrPort{inExpected}},
		{"INNER", INNER, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Metadata{
				Type:      tc.typ,
				PacketDst: packetDst,
				InIP:      inIP,
				InPort:    7890,
			}
			got := m.FlowPeers()
			if len(got) != len(tc.want) {
				t.Fatalf("FlowPeers() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("FlowPeers()[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
