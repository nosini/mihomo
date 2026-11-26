package tunnel

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/net/packet"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

// testOutbound opens a real loopback UDP socket for every session, so that
// sessions show as distinct source ports at the destination.
type testOutbound struct {
	C.Proxy
	mu    sync.Mutex
	conns []*net.UDPConn
}

func (o *testOutbound) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.conns = append(o.conns, conn)
	o.mu.Unlock()
	return &testPacketConn{EnhancePacketConn: packet.NewEnhancePacketConn(conn)}, nil
}

type testPacketConn struct {
	packet.EnhancePacketConn
}

func (*testPacketConn) Chains() C.Chain                               { return C.Chain{"DIRECT"} }
func (*testPacketConn) ProviderChains() C.Chain                       { return nil }
func (*testPacketConn) AppendToChains(C.ProxyAdapter)                 {}
func (*testPacketConn) RemoteDestination() string                     { return "" }
func (*testPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

// countingRule counts the rule matches, one per resolveMetadata, and matches
// nothing, so DIRECT is used.
type countingRule struct{ matches atomic.Int32 }

func (r *countingRule) RuleType() C.RuleType { return C.MATCH }
func (r *countingRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	r.matches.Add(1)
	return false, ""
}
func (r *countingRule) Adapter() string         { return "DIRECT" }
func (r *countingRule) Payload() string         { return "" }
func (r *countingRule) ProviderNames() []string { return nil }

type testPacket struct {
	data    []byte
	source  netip.AddrPort
	replies chan []byte
}

func (p *testPacket) Data() []byte { return p.data }
func (p *testPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	p.replies <- append([]byte(nil), b...)
	return len(b), nil
}
func (p *testPacket) Drop()               {}
func (p *testPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.source) }

// Packets from one source address and port keep their session while their
// recorded sender stays the same, as a cone NAT does, and open a new one, with
// its own rule match and outbound, when another sender uses the port.
func TestUDPSessionPerSender(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	destination := server.LocalAddr().(*net.UDPAddr).AddrPort()

	outbound := &testOutbound{}
	rule := &countingRule{}
	oldProxies, oldProviders := UpdateProxies(map[string]C.Proxy{"DIRECT": outbound}, nil)
	oldRules, oldSubRules, oldRuleProviders := UpdateRules([]C.Rule{rule}, nil, nil)
	oldStatus := status.Load()
	OnRunning()
	owners := map[string]process.FlowOwner{
		"alpha": {Tgid: 100, UID: 1000, BootNs: 1},
		"beta":  {Tgid: 200, UID: 1000, BootNs: 2},
		"wine":  {Tgid: 200, UID: 1000, BootNs: 2, WineSocket: 7, WineServer: 300, WineClient: 301, WineStatus: 1},
	}
	var sender atomic.Value
	findFlowOwner = func(string, netip.Addr, int, ...netip.AddrPort) process.FlowOwner {
		return owners[sender.Load().(string)]
	}
	defer func() {
		findFlowOwner = process.FindFlowOwner
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		status.Store(oldStatus)
	}()

	source := netip.MustParseAddrPort("198.18.0.1:5000")
	replies := make(chan []byte, 16)
	send := func(from, data string) netip.AddrPort {
		t.Helper()
		sender.Store(from)
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5,
			SrcIP: source.Addr(), SrcPort: source.Port(), DstIP: destination.Addr(), DstPort: destination.Port()}
		handleUDPConn(C.NewPacketAdapter(&testPacket{data: []byte(data), source: source, replies: replies}, metadata))
		buf := make([]byte, 64)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := server.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		if string(buf[:n]) != data {
			t.Fatalf("got %q, want %q", buf[:n], data)
		}
		return addr
	}
	reply := func(to netip.AddrPort, data string) {
		t.Helper()
		if _, err := server.WriteToUDPAddrPort([]byte(data), to); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-replies:
			if string(got) != data {
				t.Fatalf("reply %q, want %q", got, data)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no reply %q", data)
		}
	}

	first := send("alpha", "a1")
	if again := send("alpha", "a2"); again != first {
		t.Errorf("same sender left from %s, then %s; want one session", first, again)
	}
	reply(first, "to alpha")
	if n := rule.matches.Load(); n != 1 {
		t.Errorf("%d rule matches for one sender, want 1", n)
	}

	second := send("beta", "b1")
	if second == first {
		t.Fatalf("another sender left through the first session's outbound %s", first)
	}
	if n := rule.matches.Load(); n != 2 {
		t.Errorf("%d rule matches after another sender, want 2", n)
	}
	if again := send("beta", "b2"); again != second {
		t.Errorf("second sender left from %s, then %s", second, again)
	}
	reply(second, "to beta")

	// The replaced session's outbound is closed.
	outbound.mu.Lock()
	closed := outbound.conns[0]
	outbound.mu.Unlock()
	if _, err := closed.WriteToUDPAddrPort([]byte("x"), destination); err == nil {
		t.Error("the replaced session's outbound is still open")
	}

	// A Windows program behind the same relay process is another sender.
	if third := send("wine", "w1"); third == second {
		t.Errorf("a Wine program's packets left through the relay's own session")
	}
	if n := rule.matches.Load(); n != 3 {
		t.Errorf("%d rule matches after a Wine sender, want 3", n)
	}
}

// Without a recorded sender, packets keep one session per source address and
// port, as before.
func TestUDPSessionUnknownSender(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	destination := server.LocalAddr().(*net.UDPAddr).AddrPort()
	rule := &countingRule{}
	oldProxies, oldProviders := UpdateProxies(map[string]C.Proxy{"DIRECT": &testOutbound{}}, nil)
	oldRules, oldSubRules, oldRuleProviders := UpdateRules([]C.Rule{rule}, nil, nil)
	oldStatus := status.Load()
	OnRunning()
	findFlowOwner = func(string, netip.Addr, int, ...netip.AddrPort) process.FlowOwner { return process.FlowOwner{} }
	defer func() {
		findFlowOwner = process.FindFlowOwner
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		status.Store(oldStatus)
	}()

	source := netip.MustParseAddrPort("198.18.0.1:5001")
	var from []netip.AddrPort
	for _, data := range []string{"one", "two"} {
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5,
			SrcIP: source.Addr(), SrcPort: source.Port(), DstIP: destination.Addr(), DstPort: destination.Port()}
		handleUDPConn(C.NewPacketAdapter(&testPacket{data: []byte(data), source: source, replies: make(chan []byte, 1)}, metadata))
		buf := make([]byte, 64)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, addr, err := server.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatal(err)
		}
		from = append(from, addr)
	}
	if from[0] != from[1] || rule.matches.Load() != 1 {
		t.Errorf("sources %v with %d matches, want one session", from, rule.matches.Load())
	}
}
