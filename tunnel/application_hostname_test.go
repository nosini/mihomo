package tunnel

import (
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
)

type applicationRouteRule struct {
	C.Rule
	after func(*C.Metadata)
}

type applicationTestProxy struct {
	C.Proxy
	name string
}

func (p applicationTestProxy) Name() string                   { return p.name }
func (applicationTestProxy) Type() C.AdapterType              { return C.Direct }
func (applicationTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func (r applicationRouteRule) Match(m *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	matched, adapter := r.Rule.Match(m, helper)
	if matched {
		r.after(m)
	}
	return matched, adapter
}

func TestApplicationHostnamePostMatchRollback(t *testing.T) {
	oldMode, oldRules, oldProxies, oldSniffing, oldMapper := mode, rules, proxies, sniffingEnable, resolver.DefaultHostMapper
	defer func() {
		mode, rules, proxies, sniffingEnable, resolver.DefaultHostMapper = oldMode, oldRules, oldProxies, oldSniffing, oldMapper
	}()
	mode, sniffingEnable, resolver.DefaultHostMapper = Rule, false, nil
	proxies = map[string]C.Proxy{}
	for _, name := range []string{"NAMED", "DIRECT"} {
		proxies[name] = applicationTestProxy{name: name}
	}
	for _, scenario := range []string{"healthy", "revoked-in-match", "metadata-changed-in-match"} {
		t.Run(scenario, func(t *testing.T) {
			valid, checks, matches := true, 0, 0
			m := &C.Metadata{NetWork: C.TCP, Type: C.REDIR, SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 12345, DstIP: netip.MustParseAddr("192.0.2.20"), DstPort: 443}
			original := m.DstIP
			if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, func() bool { checks++; return valid }); err != nil {
				t.Fatal(err)
			}
			rules = []C.Rule{applicationRouteRule{Rule: R.NewDomain("route.invalid", "NAMED"), after: func(m *C.Metadata) {
				matches++
				if scenario == "revoked-in-match" {
					valid = false
				}
				if scenario == "metadata-changed-in-match" {
					m.Host, m.SniffHost, m.DstIP = "other.invalid", "other.invalid", netip.MustParseAddr("192.0.2.99")
				}
			}}}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			peeks := 0
			proxy, _, err := resolveTCPMetadata(N.NewBufferedConn(a), m, func() { peeks++ })
			want := "DIRECT"
			if scenario == "healthy" {
				want = "NAMED"
			}
			if err != nil || proxy.Name() != want || matches != 1 || peeks != 1 || m.Host != "" || m.SniffHost != "" || m.DstIP != original {
				t.Fatalf("unsafe route: %v, metadata %+v; matches %d, peeks %d", err, m, matches, peeks)
			}
			if scenario != "metadata-changed-in-match" && checks != 1 {
				t.Fatal("missing post-match validation")
			}
			if want == "DIRECT" && m.HasApplicationHostname() {
				t.Fatal("fallback retained application evidence")
			}
		})
	}
}

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
				if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, func() bool { return true }); err != nil {
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

type applicationMappingMapper struct{ resolver.Enhancer }

func (applicationMappingMapper) MappingEnabled() bool                   { return true }
func (applicationMappingMapper) IsFakeIP(netip.Addr) bool               { return false }
func (applicationMappingMapper) FindHostByIP(netip.Addr) (string, bool) { return "hint.invalid", true }

func TestApplicationHostnameRollbackRestoresHostsPolicy(t *testing.T) {
	oldMode, oldRules, oldProxies, oldSniffing, oldMapper, oldHosts := mode, rules, proxies, sniffingEnable, resolver.DefaultHostMapper, resolver.DefaultHosts
	defer func() {
		mode, rules, proxies, sniffingEnable, resolver.DefaultHostMapper, resolver.DefaultHosts = oldMode, oldRules, oldProxies, oldSniffing, oldMapper, oldHosts
	}()
	mode, sniffingEnable = Rule, false
	resolver.DefaultHostMapper = applicationMappingMapper{}
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	wrong := netip.MustParseAddr("192.0.2.99")
	value, _ := resolver.NewHostValueByIPs([]netip.Addr{wrong})
	resolver.DefaultHosts.Insert("hint.invalid", value)
	proxies = map[string]C.Proxy{"NAMED": applicationTestProxy{name: "NAMED"}, "DIRECT": applicationTestProxy{name: "DIRECT"}}
	rules = []C.Rule{R.NewDomain("route.invalid", "NAMED")}
	m := &C.Metadata{NetWork: C.TCP, Type: C.REDIR, SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 12345, DstIP: netip.MustParseAddr("192.0.2.20"), DstPort: 443}
	m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, func() bool { return false })
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	proxy, _, err := resolveTCPMetadata(N.NewBufferedConn(a), m, func() {})
	if err != nil || proxy.Name() != "DIRECT" || m.Host != "hint.invalid" || m.DstIP != wrong || m.HasApplicationHostname() {
		t.Fatalf("fallback retained application-specific effects: %+v, %v", m, err)
	}
}
