package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/net/packet"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
)

// testOutbound opens a real loopback UDP socket for every session, so that
// sessions show as distinct source ports at the destination.
type testOutbound struct {
	C.Proxy
	mu    sync.Mutex
	conns []*net.UDPConn
	// dials counts ListenPacketContext calls; fail makes them fail.
	dials atomic.Int32
	fail  atomic.Bool
}

func (o *testOutbound) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	o.dials.Add(1)
	if o.fail.Load() {
		// Wrapped as a loopback rejection, which stops handleUDPConn's
		// dial retries, so a failing dial is a single call.
		return nil, fmt.Errorf("test outbound: %w", loopback.ErrReject)
	}
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

// Name answers the dial-failure log line, which the embedded nil C.Proxy
// cannot.
func (*testOutbound) Name() string { return "DIRECT" }

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

// A replacement whose dial fails holds the entry with the TPROXY local conns
// of its address, so its teardown closes them instead of leaking the
// write-back sockets with their reader goroutines.
func TestUDPSessionFailedDialClosesLocalConns(t *testing.T) {
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

	source := netip.MustParseAddrPort("198.18.0.2:5002")
	key := source.String() // the packet adapter's NAT key is its local address
	replies := make(chan []byte, 16)
	send := func(from, data string) {
		sender.Store(from)
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5,
			SrcIP: source.Addr(), SrcPort: source.Port(), DstIP: destination.Addr(), DstPort: destination.Port()}
		handleUDPConn(C.NewPacketAdapter(&testPacket{data: []byte(data), source: source, replies: replies}, metadata))
	}

	send("alpha", "a1")
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "a1" {
		t.Fatalf("first packet %q, %v", buf[:n], err)
	}

	// A local conn writing replies back to the session's source, as the
	// TPROXY inbound records one.
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if !natTable.AddForLocalConn(key, "1.2.3.4:443", local) {
		t.Fatal("no entry to hold the local conn")
	}

	outbound.fail.Store(true)
	send("beta", "b1")

	_ = local.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := local.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read on the local conn: %v, want %v", err, net.ErrClosed)
	}
	if conn := natTable.GetForLocalConn(key, "1.2.3.4:443"); conn != nil {
		t.Error("the entry is still in the NAT table")
	}
}

// quicInitialDatagram builds a QUIC v1 long-header Initial with an
// undecryptable payload: the sniffer keeps waiting for more fragments
// instead of deciding, as one does behind a client that has more to send.
func quicInitialDatagram() []byte {
	datagram := []byte{
		0xc0,                   // long header, fixed bit, Initial
		0x00, 0x00, 0x00, 0x01, // version 1
		0x08, // destination connection ID length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, // source connection ID length
		0x00, // token length
		0x18, // packet length
	}
	return append(datagram, make([]byte, 0x18)...)
}

// A session closed while its sniffer waits for more packets is not matched
// against the rules again and not dialed: the packet that replaced it owns the
// route, and the dead session leaves through nothing.
func TestUDPSessionClosedDuringSniffNotDialed(t *testing.T) {
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
	}
	var sender atomic.Value
	findFlowOwner = func(string, netip.Addr, int, ...netip.AddrPort) process.FlowOwner {
		return owners[sender.Load().(string)]
	}
	oldDispatcher, oldSniffing := snifferDispatcher, sniffingEnable
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable: true,
		Sniffers: map[snifferTypes.Type]sniffer.SnifferConfig{
			snifferTypes.QUIC: {Ports: utils.IntRanges[uint16]{utils.NewRange[uint16](destination.Port(), destination.Port())}},
		},
		ParsePureIp: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	UpdateSniffer(dispatcher)
	defer func() {
		snifferDispatcher = oldDispatcher
		sniffingEnable = oldSniffing
		findFlowOwner = process.FindFlowOwner
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		status.Store(oldStatus)
	}()

	source := netip.MustParseAddrPort("198.18.0.3:5003")
	replies := make(chan []byte, 16)
	send := func(from string, data []byte) {
		sender.Store(from)
		metadata := &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5,
			SrcIP: source.Addr(), SrcPort: source.Port(), DstIP: destination.Addr(), DstPort: destination.Port()}
		handleUDPConn(C.NewPacketAdapter(&testPacket{data: data, source: source, replies: replies}, metadata))
	}

	send("alpha", quicInitialDatagram())
	// Another sender replaces the session while its sniff waits.
	send("beta", []byte("b1"))

	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "b1" {
		t.Fatalf("replacement packet %q, %v", buf[:n], err)
	}
	// A dial the closed session might still start would reach the outbound
	// right after its sniff returned, so wait out that window.
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
		if dials := outbound.dials.Load(); dials > 1 {
			t.Fatalf("%d dial attempts, want 1", dials)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := rule.matches.Load(); n != 1 {
		t.Errorf("%d rule matches, want 1", n)
	}
	if n := outbound.dials.Load(); n != 1 {
		t.Errorf("%d dial attempts, want 1", n)
	}
}
