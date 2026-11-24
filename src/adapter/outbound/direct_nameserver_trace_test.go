package outbound_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	_ "github.com/metacubex/mihomo/config" // sets dns.ParseNameServer
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

// countingResolver stands in for every resolver a failing outbound must not
// fall back to: the main list, dns.direct-nameserver and the system resolver.
// It counts its lookups and answers with a canary address, so a single
// fallback is visible both in the counter and in the address dialed. The
// stand-ins are installed once for the whole package before any test runs:
// the resolvers are package globals that dials read concurrently, so
// rewriting them per test would race with queries still in flight.
var sharedResolver = &countingResolver{ip: netip.MustParseAddr("192.0.2.66")}

func TestMain(m *testing.M) {
	resolver.DefaultResolver = sharedResolver
	resolver.DirectHostResolver = sharedResolver
	resolver.SystemResolver = sharedResolver
	os.Exit(m.Run())
}

type countingResolver struct {
	mu      sync.Mutex
	lookups int
	ip      netip.Addr
}

func (r *countingResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.answered(host)
}

func (r *countingResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.answered(host)
}

func (r *countingResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.answered(host)
}

func (r *countingResolver) answered(host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.lookups++
	r.mu.Unlock()
	return []netip.Addr{r.ip}, nil
}

func (r *countingResolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, fmt.Errorf("no ech for %s", host)
}

func (r *countingResolver) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return nil, fmt.Errorf("no exchange for %s", m.Question[0].Name)
}

func (r *countingResolver) Invalid() bool    { return true }
func (r *countingResolver) ClearCache()      {}
func (r *countingResolver) ResetConnection() {}

func (r *countingResolver) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

// resolveUDPTrace resolves host through p, returning the metadata the
// connection tracker will expose: the same object, filled in during the dial.
func resolveUDPTrace(t *testing.T, p C.Proxy, host string) *C.Metadata {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, Host: host, DstPort: 9}
	pc, err := p.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	return metadata
}

// assertQuerySource checks that the metadata's recorded local address is the
// one the nameserver saw the query arrive from. A UDP query socket can be
// bound to the wildcard address, so only its port has to match; a TCP query
// connection has a concrete source address.
func assertQuerySource(t *testing.T, md *C.OutboundDNS, serverSource string, concrete bool) {
	t.Helper()
	sourceAddr, err := net.ResolveUDPAddr("udp", serverSource)
	if err != nil {
		t.Fatalf("nameserver saw an unreadable source %q: %v", serverSource, err)
	}
	if concrete {
		localAddr, err := net.ResolveTCPAddr("tcp", md.LocalAddr)
		if err != nil || !localAddr.IP.IsLoopback() {
			t.Errorf("local address %q is not a loopback address: %v", md.LocalAddr, err)
			return
		}
		if localAddr.IP.String() != sourceAddr.IP.String() || localAddr.Port != sourceAddr.Port {
			t.Errorf("local address %q does not match the source the nameserver saw (%s)", md.LocalAddr, serverSource)
		}
		return
	}
	_, port, err := net.SplitHostPort(md.LocalAddr)
	if err != nil {
		t.Fatalf("local address %q is not a host:port pair: %v", md.LocalAddr, err)
	}
	if p, _ := strconv.Atoi(port); p != sourceAddr.Port {
		t.Errorf("local address %q does not name the port the nameserver saw (%s)", md.LocalAddr, serverSource)
	}
}

// Two exits with one nameserver each: the same name is resolved through both,
// and each nameserver must see its own query, answered from its own source
// address, while no shared resolver is used.
func TestDirectNameserverLeakMetadata(t *testing.T) {
	sharedBefore := sharedResolver.total()
	a := startCountingDNSOn(t, "127.0.0.2", netip.MustParseAddr("127.0.0.1"))
	b := startCountingDNSOn(t, "127.0.0.3", netip.MustParseAddr("127.0.0.1"))
	exitA := newDirect(t, "exit-a", map[string]any{"nameserver": []any{"udp://" + a.addr}})
	exitB := newDirect(t, "exit-b", map[string]any{"nameserver": []any{"udp://" + b.addr}})

	mdA := resolveUDPTrace(t, exitA, "leak.test")
	mdB := resolveUDPTrace(t, exitB, "leak.test")

	for _, md := range []*C.Metadata{mdA, mdB} {
		if md.DstIP != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("%s resolved %s, want its own nameserver's answer", md.Host, md.DstIP)
		}
		if md.OutboundDNS == nil {
			t.Fatalf("no outbound DNS metadata for %s", md.Host)
		}
		if md.OutboundDNS.Interface != "" {
			t.Errorf("interface %q recorded without interface-name", md.OutboundDNS.Interface)
		}
	}
	if mdA.OutboundDNS.Server != "udp://"+a.addr || mdA.OutboundDNS.Cached {
		t.Errorf("exit-a recorded %v, want %s uncached", mdA.OutboundDNS, "udp://"+a.addr)
	}
	assertQuerySource(t, mdA.OutboundDNS, a.source("leak.test"), false)
	if mdB.OutboundDNS.Server != "udp://"+b.addr || mdB.OutboundDNS.Cached {
		t.Errorf("exit-b recorded %v, want %s uncached", mdB.OutboundDNS, "udp://"+b.addr)
	}
	assertQuerySource(t, mdB.OutboundDNS, b.source("leak.test"), false)
	if got := a.count("leak.test"); got != 1 {
		t.Errorf("exit-a's nameserver saw %d queries, want 1", got)
	}
	if got := b.count("leak.test"); got != 1 {
		t.Errorf("exit-b's nameserver saw %d queries, want 1", got)
	}
	if sharedResolver.total() != sharedBefore {
		t.Errorf("a shared resolver answered %d lookups, want 0", sharedResolver.total()-sharedBefore)
	}

	// The next lookup through the same exit is answered from its cache: no
	// new query, and the metadata reports the query that filled the entry.
	mdCached := resolveUDPTrace(t, exitA, "leak.test")
	if !mdCached.OutboundDNS.Cached || mdCached.OutboundDNS.Server != "udp://"+a.addr {
		t.Errorf("cached lookup recorded %v", mdCached.OutboundDNS)
	}
	assertQuerySource(t, mdCached.OutboundDNS, a.source("leak.test"), false)
	if got := a.count("leak.test"); got != 1 {
		t.Errorf("exit-a's nameserver saw %d queries after the cached lookup, want 1", got)
	}
	if sharedResolver.total() != sharedBefore {
		t.Errorf("a shared resolver answered %d lookups after the cached lookup, want 0",
			sharedResolver.total()-sharedBefore)
	}
}

// A nameserver over TCP reports the concrete source address of the query.
func TestDirectNameserverLeakMetadataTCPTransport(t *testing.T) {
	server := startCountingTCPDNSOn(t, "127.0.0.2", netip.MustParseAddr("127.0.0.1"))
	exit := newDirect(t, "exit-a", map[string]any{"nameserver": []any{"tcp://" + server.addr}})

	md := resolveUDPTrace(t, exit, "tcp.transport.test")
	if md.OutboundDNS == nil || md.OutboundDNS.Server != "tcp://"+server.addr {
		t.Fatalf("recorded %v, want nameserver %s", md.OutboundDNS, server.addr)
	}
	if md.OutboundDNS.Cached {
		t.Errorf("recorded a cached answer: %v", md.OutboundDNS)
	}
	assertQuerySource(t, md.OutboundDNS, server.source("tcp.transport.test"), true)
	if got := server.count("tcp.transport.test"); got != 1 {
		t.Errorf("nameserver saw %d queries, want 1", got)
	}
}

// A TCP dial through an exit with its own nameserver records the same
// metadata on the stream path.
func TestDirectNameserverLeakMetadataTCP(t *testing.T) {
	server := startCountingDNSOn(t, "127.0.0.2", netip.MustParseAddr("127.0.0.1"))
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

	exit := newDirect(t, "exit-a", map[string]any{"nameserver": []any{"udp://" + server.addr}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.TCP, Host: "tcp.leak.test", DstPort: port}
	c, err := exit.DialContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	if metadata.OutboundDNS == nil || metadata.OutboundDNS.Server != "udp://"+server.addr {
		t.Fatalf("TCP dial recorded %v, want nameserver %s", metadata.OutboundDNS, server.addr)
	}
	if metadata.OutboundDNS.Cached {
		t.Errorf("TCP dial recorded a cached answer: %v", metadata.OutboundDNS)
	}
	if got := server.count("tcp.leak.test"); got != 1 {
		t.Errorf("nameserver saw %d queries, want 1", got)
	}
}

// When every nameserver of an outbound fails, the dial fails: it is not
// answered by dns.direct-nameserver, the main nameserver list or the system
// resolver.
func TestDirectNameserverFailClosed(t *testing.T) {
	sharedBefore := sharedResolver.total()
	failingA := startFailingDNS(t, "127.0.0.2")
	failingB := startFailingDNS(t, "127.0.0.3")
	p := newDirect(t, "exit", map[string]any{
		"nameserver": []any{"udp://" + failingA.addr, "udp://" + failingB.addr},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, Host: "unreachable.test", DstPort: 9}
	pc, err := p.ListenPacketContext(ctx, metadata)
	if err == nil {
		_ = pc.Close()
		t.Fatal("dial succeeded although every nameserver failed")
	}
	if failingA.count("unreachable.test") == 0 || failingB.count("unreachable.test") == 0 {
		t.Errorf("not every nameserver was asked: %d and %d queries",
			failingA.count("unreachable.test"), failingB.count("unreachable.test"))
	}
	if sharedResolver.total() != sharedBefore {
		t.Errorf("a shared resolver answered %d lookups, want 0", sharedResolver.total()-sharedBefore)
	}
	if metadata.OutboundDNS != nil {
		t.Errorf("failed dial recorded %v", metadata.OutboundDNS)
	}
}

// A direct outbound without the option keeps resolving through
// dns.direct-nameserver and records no DNS metadata of its own.
func TestDirectNameserverMetadataOnlyForOwnResolver(t *testing.T) {
	sharedBefore := sharedResolver.total()
	p := newDirect(t, "plain", nil)

	metadata := resolveUDPTrace(t, p, "plain.test")
	if metadata.OutboundDNS != nil {
		t.Errorf("recorded %v without a nameserver list", metadata.OutboundDNS)
	}
	if metadata.DstIP != sharedResolver.ip {
		t.Errorf("resolved %s, want the shared resolver's %s", metadata.DstIP, sharedResolver.ip)
	}
	if sharedResolver.total() == sharedBefore {
		t.Error("the shared resolver was not used")
	}
}
