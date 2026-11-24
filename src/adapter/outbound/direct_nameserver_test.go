package outbound_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	_ "github.com/metacubex/mihomo/config" // sets dns.ParseNameServer
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

// countingDNS answers every A query with answer and counts questions per name.
// With servfail set it answers every question with SERVFAIL instead. It also
// records the address each question arrived from.
type countingDNS struct {
	mu       sync.Mutex
	queries  map[string]int
	sources  map[string]string
	answer   netip.Addr
	addr     string
	servfail bool
}

func startCountingDNS(t *testing.T, answer netip.Addr) *countingDNS {
	return startCountingDNSOn(t, "127.0.0.1", answer)
}

func startCountingDNSOn(t *testing.T, host string, answer netip.Addr) *countingDNS {
	return startDNSOn(t, host, answer, false)
}

// startFailingDNS counts its questions and fails every one of them.
func startFailingDNS(t *testing.T, host string) *countingDNS {
	return startDNSOn(t, host, netip.Addr{}, true)
}

func startDNSOn(t *testing.T, host string, answer netip.Addr, servfail bool) *countingDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := newCountingDNS(answer, pc.LocalAddr().String(), servfail)
	server := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		m := new(D.Msg)
		q := req.Question[0]
		s.record(q.Name, w.RemoteAddr())
		if s.servfail {
			m.SetRcode(req, D.RcodeServerFailure)
		} else {
			m.SetReply(req)
			if q.Qtype == D.TypeA {
				m.Answer = append(m.Answer, &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
					A:   s.answer.AsSlice(),
				})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return s
}

func newCountingDNS(answer netip.Addr, addr string, servfail bool) *countingDNS {
	return &countingDNS{
		queries:  map[string]int{},
		sources:  map[string]string{},
		answer:   answer,
		addr:     addr,
		servfail: servfail,
	}
}

// record counts one question for name and remembers where it arrived from.
func (s *countingDNS) record(name string, remote net.Addr) {
	s.mu.Lock()
	s.queries[name]++
	s.sources[name] = remote.String()
	s.mu.Unlock()
}

func (s *countingDNS) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[D.Fqdn(name)]
}

// source returns the address the last question for name arrived from.
func (s *countingDNS) source(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sources[D.Fqdn(name)]
}

func newDirect(t *testing.T, name string, extra map[string]any) C.Proxy {
	t.Helper()
	mapping := map[string]any{"name": name, "type": "direct", "udp": true, "ip-version": "ipv4"}
	for k, v := range extra {
		mapping[k] = v
	}
	p, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func resolveUDP(t *testing.T, p C.Proxy, host string) (netip.Addr, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, Host: host, DstPort: 9}
	pc, err := p.ListenPacketContext(ctx, metadata)
	if err != nil {
		return netip.Addr{}, err
	}
	_ = pc.Close()
	return metadata.DstIP, nil
}

func TestDirectNameserverPerOutbound(t *testing.T) {
	server := startCountingDNS(t, netip.MustParseAddr("127.0.0.1"))
	ns := []any{"udp://" + server.addr}
	a := newDirect(t, "exit-a", map[string]any{"nameserver": ns})
	b := newDirect(t, "exit-b", map[string]any{"nameserver": ns})

	for _, p := range []C.Proxy{a, a, b} {
		ip, err := resolveUDP(t, p, "example.test")
		if err != nil {
			t.Fatalf("%s: %v", p.Name(), err)
		}
		if ip != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("%s resolved %s", p.Name(), ip)
		}
	}
	// One query per outbound: the second lookup through exit-a is cached,
	// the lookup through exit-b is not answered from exit-a's cache.
	if got := server.count("example.test"); got != 2 {
		t.Fatalf("server saw %d A queries, want 2", got)
	}
}

func TestDirectNameserverReresolvesTunnelAnswer(t *testing.T) {
	server := startCountingDNS(t, netip.MustParseAddr("127.0.0.1"))
	p := newDirect(t, "exit", map[string]any{"nameserver": []any{"udp://" + server.addr}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Resolved earlier by the main resolver, e.g. for an IP rule.
	metadata := &C.Metadata{NetWork: C.UDP, Host: "example.test", DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 9}
	pc, err := p.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if metadata.DstIP != netip.MustParseAddr("127.0.0.1") || server.count("example.test") != 1 {
		t.Fatalf("got %s after %d queries, want the outbound's own answer", metadata.DstIP, server.count("example.test"))
	}
}

func TestDirectNameserverTCPDial(t *testing.T) {
	server := startCountingDNS(t, netip.MustParseAddr("127.0.0.1"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// TCP queries exercise the outbound's stream path to the nameserver.
	tcpServer := startCountingTCPDNS(t, netip.MustParseAddr("127.0.0.1"))
	for _, ns := range []string{"udp://" + server.addr, "tcp://" + tcpServer.addr} {
		p := newDirect(t, "exit", map[string]any{"nameserver": []any{ns}})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := p.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "web.test", DstPort: port})
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", ns, err)
		}
		_ = c.Close()
	}
	if server.count("web.test") == 0 || tcpServer.count("web.test") == 0 {
		t.Fatalf("lookups: udp %d, tcp %d", server.count("web.test"), tcpServer.count("web.test"))
	}
}

func startCountingTCPDNS(t *testing.T, answer netip.Addr) *countingDNS {
	return startCountingTCPDNSOn(t, "127.0.0.1", answer)
}

func startCountingTCPDNSOn(t *testing.T, host string, answer netip.Addr) *countingDNS {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := newCountingDNS(answer, ln.Addr().String(), false)
	server := &D.Server{Listener: ln, Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		m := new(D.Msg)
		m.SetReply(req)
		q := req.Question[0]
		s.record(q.Name, w.RemoteAddr())
		if q.Qtype == D.TypeA {
			m.Answer = append(m.Answer, &D.A{
				Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
				A:   answer.AsSlice(),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return s
}

// The nameserver is dialed with the outbound's own options. Loopback
// destinations are never bound to an interface, so use a documentation
// address: binding it to a missing interface fails with ENODEV before any
// packet is sent, instead of the query leaving another way.
func TestDirectNameserverUsesOutboundInterface(t *testing.T) {
	p := newDirect(t, "exit", map[string]any{
		"nameserver":     []any{"udp://192.0.2.53", "tcp://192.0.2.53"},
		"interface-name": "mihomo-none0",
	})
	_, err := resolveUDP(t, p, "example.test")
	if err == nil || !strings.Contains(err.Error(), "no such device") {
		t.Fatalf("got %v, want a bind failure on the outbound's interface", err)
	}
}

func TestDirectNameserverValidation(t *testing.T) {
	for _, ns := range []string{
		"udp://10.0.0.3",
		"10.0.0.3",
		"tcp://10.0.0.3:5353",
		"tls://1.1.1.1",
		"https://1.1.1.1/dns-query",
		"quic://[2606:4700:4700::1111]",
	} {
		if _, err := adapter.ParseProxy(map[string]any{"name": "ok", "type": "direct", "nameserver": []any{ns}}); err != nil {
			t.Errorf("%s: %v", ns, err)
		}
	}
	for ns, want := range map[string]string{
		"udp://dns.example":         "not an IP address",
		"https://dns.example/query": "not an IP address",
		"udp://10.0.0.3#DNS":        "not allowed",
		"system://":                 "not supported",
		"dhcp://eth0":               "not supported",
		"rcode://refused":           "not supported",
		"ftp://10.0.0.3":            "unsupport scheme",
	} {
		_, err := adapter.ParseProxy(map[string]any{"name": "bad", "type": "direct", "nameserver": []any{ns}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", ns, err, want)
		}
	}
}
