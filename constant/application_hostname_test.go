package constant_test

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/transport/socks5"
)

func applicationMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, Type: C.REDIR,
		SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 12345,
		DstIP: netip.MustParseAddr("192.0.2.20"), DstPort: 443}
}

func TestApplicationHostnameSelection(t *testing.T) {
	for _, tc := range []struct {
		name, host, sniff, want string
		mode                    C.DNSMode
		role                    C.ApplicationHostnameRole
	}{
		{name: "plain", want: "route.invalid"},
		{name: "same sniff", sniff: "ROUTE.invalid.", want: "route.invalid"},
		{name: "conflicting sniff", sniff: "other.invalid", want: "other.invalid"},
		{name: "verified inner", sniff: "outer.invalid", role: C.ApplicationHostnameECHInner, want: "route.invalid"},
		{name: "DNS hint", host: "hint.invalid", mode: C.DNSMapping, want: "route.invalid"},
		{name: "explicit", host: "explicit.invalid", want: "explicit.invalid"},
		{name: "explicit keeps existing sniff", host: "explicit.invalid", sniff: "sniff.invalid", want: "sniff.invalid"},
		{name: "Fake-IP", host: "fake.invalid", mode: C.DNSFakeIP, want: "fake.invalid"},
		{name: "Fake-IP keeps existing sniff", host: "fake.invalid", sniff: "sniff.invalid", mode: C.DNSFakeIP, want: "sniff.invalid"},
		{name: "hosts destination", host: "hosts.invalid", mode: C.DNSHosts, want: "hosts.invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := applicationMetadata()
			role := tc.role
			if role == 0 {
				role = C.ApplicationHostnameTLS
			}
			if err := setApplicationHostname(m, "Route.Invalid.", role); err != nil {
				t.Fatal(err)
			}
			m.Host, m.SniffHost, m.DNSMode = tc.host, tc.sniff, tc.mode
			if got := m.RuleHost(); got != tc.want {
				t.Fatalf("RuleHost = %q, want %q", got, tc.want)
			}
			// The ordinary domain matcher consumes the selected name directly.
			if match, _ := R.NewDomain(tc.want, "NAMED").Match(m, C.RuleMatchHelper{}); !match {
				t.Fatal("domain rule missed selected name")
			}
		})
	}
}

func TestApplicationHostnameValidation(t *testing.T) {
	for _, name := range []string{"", ".", "a..b", "name..", "-name.invalid", "name-.invalid", "name_1.invalid", "*.invalid", "a/b", "a:443", "a\x00b", " a.invalid", "a.invalid\n", "é.invalid", "127.0.0.1", "::1", strings.Repeat("a", 64) + ".invalid", strings.Repeat("a.", 127) + "a"} {
		t.Run(name, func(t *testing.T) {
			m := applicationMetadata()
			if err := setApplicationHostname(m, name, C.ApplicationHostnameTLS); err == nil || m.RuleHost() != "" {
				t.Fatalf("accepted %q", name)
			}
		})
	}
	for _, name := range []string{"a", "xn--bcher-kva.invalid", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "."} {
		m := applicationMetadata()
		if err := setApplicationHostname(m, name, C.ApplicationHostnameTLS); err != nil {
			t.Fatalf("rejected %q: %v", name, err)
		}
	}
	m := applicationMetadata()
	if err := setApplicationHostname(m, "route.invalid", 0); err == nil {
		t.Fatal("accepted unspecified provenance")
	}
}

func TestApplicationHostnameScopeAndConflict(t *testing.T) {
	for _, mutate := range []func(*C.Metadata){
		func(m *C.Metadata) { m.NetWork = C.UDP },
		func(m *C.Metadata) { m.Type = C.TPROXY },
		func(m *C.Metadata) { m.SrcIP = netip.MustParseAddr("192.0.2.11") },
		func(m *C.Metadata) { m.SrcPort++ },
		func(m *C.Metadata) { m.DstIP = netip.MustParseAddr("192.0.2.21") },
		func(m *C.Metadata) { m.DstPort++ },
	} {
		m := applicationMetadata()
		if err := setApplicationHostname(m, "route.invalid", C.ApplicationHostnameTLS); err != nil {
			t.Fatal(err)
		}
		clone := m.Clone()
		mutate(clone)
		if clone.ApplicationHostname() != "" {
			t.Fatal("evidence survived a connection identity change")
		}
		if m.RuleHost() != "route.invalid" {
			t.Fatal("clone changed original evidence")
		}
	}
	for _, replacement := range []string{"other.invalid", "bad name"} {
		m := applicationMetadata()
		setApplicationHostname(m, "route.invalid", C.ApplicationHostnameTLS)
		if err := setApplicationHostname(m, replacement, C.ApplicationHostnameTLS); err == nil {
			t.Fatal("accepted conflicting replacement")
		}
		if err := setApplicationHostname(m, "route.invalid", C.ApplicationHostnameTLS); err == nil || m.ApplicationHostname() != "" {
			t.Fatal("conflict healed")
		}
	}
}

func TestApplicationHostnameDoesNotBecomeDialAddress(t *testing.T) {
	for _, address := range []string{"192.0.2.20", "2001:db8::20"} {
		m := applicationMetadata()
		m.DstIP = netip.MustParseAddr(address)
		setApplicationHostname(m, "route.invalid", C.ApplicationHostnameTLS)
		m.Host, m.DNSMode = "hint.invalid", C.DNSMapping
		pure := m.Pure()
		if pure.Host != "" || pure.DstIP != m.DstIP || pure.DstPort != 443 || pure.RuleHost() != "route.invalid" {
			t.Fatalf("invalid dial metadata: %+v", pure)
		}
		if pure.AddrType() == C.AtypDomainName || strings.Contains(pure.RemoteAddress(), "invalid") {
			t.Fatal("application name became dial address")
		}
		if addr := socks5.ParseAddr(pure.RemoteAddress()); addr[0] == socks5.AtypDomainName {
			t.Fatal("application name entered proxy encoding")
		}
		encoded, err := json.Marshal(m)
		if err != nil || strings.Contains(string(encoded), "route.invalid") {
			t.Fatalf("application name entered JSON: %s: %v", encoded, err)
		}
		if m.Host != "hint.invalid" {
			t.Fatal("Pure mutated original")
		}
	}
}

func setApplicationHostname(m *C.Metadata, name string, role C.ApplicationHostnameRole) error {
	return m.SetApplicationHostname(name, role, func() bool { return true })
}

func TestApplicationHostnameRequiresFreshAuthority(t *testing.T) {
	m := applicationMetadata()
	if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, nil); err == nil {
		t.Fatal("accepted an unguarded name")
	}
	m = applicationMetadata()
	valid := true
	if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, func() bool { return valid }); err != nil {
		t.Fatal(err)
	}
	clone := m.Clone()
	valid = false
	if err := m.SetApplicationHostname("route.invalid", C.ApplicationHostnameTLS, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if m.ConfirmApplicationHostname() || clone.ConfirmApplicationHostname() {
		t.Fatal("a copied or repeated name replaced its original authority")
	}
	valid = true
	if m.ConfirmApplicationHostname() || m.ApplicationHostname() != "" {
		t.Fatal("failed consumption healed")
	}
}
