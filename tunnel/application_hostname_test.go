package tunnel

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type applicationFakeIPMapper struct {
	resolver.Enhancer
	pool *fakeip.Pool
}

func (applicationFakeIPMapper) MappingEnabled() bool          { return true }
func (m applicationFakeIPMapper) IsFakeIP(ip netip.Addr) bool { return m.pool.IPNet().Contains(ip) }
func (m applicationFakeIPMapper) FindHostByIP(ip netip.Addr) (string, bool) {
	return m.pool.LookBack(ip)
}

func TestApplicationHostnameFakeIPPreprocessing(t *testing.T) {
	previous := resolver.DefaultHostMapper
	defer func() { resolver.DefaultHostMapper = previous }()
	for _, prefix := range []string{"198.18.0.0/16", "fc00::/64"} {
		t.Run(prefix, func(t *testing.T) {
			pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix(prefix), Size: 16})
			if err != nil {
				t.Fatal(err)
			}
			resolver.DefaultHostMapper = applicationFakeIPMapper{pool: pool}
			for _, known := range []bool{true, false} {
				ip := pool.Lookup("fake.invalid")
				if !known {
					ip = ip.Next()
				}
				m := &C.Metadata{NetWork: C.TCP, Type: C.REDIR,
					SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 12345,
					DstIP: ip, DstPort: 443}
				if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS); err != nil {
					t.Fatal(err)
				}
				err := preHandleMetadata(m)
				if !known {
					if err == nil {
						t.Fatal("application evidence bypassed a missing Fake-IP mapping")
					}
					continue
				}
				if err != nil || m.DNSMode != C.DNSFakeIP || m.DstIP.IsValid() || m.Host != "fake.invalid" || m.RuleHost() != "fake.invalid" || m.ApplicationHostname() != "" {
					t.Fatalf("Fake-IP semantics changed: %+v: %v", m, err)
				}
			}
		})
	}
}
