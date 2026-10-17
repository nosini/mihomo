package applicationhostname

import (
	"net"
	"net/netip"
	"testing"
)

type wrappedConn struct{ net.Conn }

func (c wrappedConn) Upstream() any { return c.Conn }

func TestAcceptedFlowThroughWrappers(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	flow, err := AcceptedFlow(wrappedConn{wrappedConn{server}})
	if err != nil || flow.Netns == 0 || flow.Source.String() != client.LocalAddr().String() || flow.Destination.String() != l.Addr().String() {
		t.Fatalf("wrong accepted flow: %+v: %v", flow, err)
	}
}

func TestTUNFlowUsesOriginalTupleInAcceptedNamespace(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	accepted, err := AcceptedFlow(server)
	if err != nil {
		t.Fatal(err)
	}
	source, destination := netip.MustParseAddrPort("[::ffff:192.0.2.1]:40000"), netip.MustParseAddrPort("192.0.2.2:443")
	flow, err := TUNFlow(wrappedConn{server}, source, destination)
	if err != nil || flow.Netns != accepted.Netns || flow.Source != netip.MustParseAddrPort("192.0.2.1:40000") || flow.Destination != destination {
		t.Fatalf("wrong TUN flow: %+v: %v", flow, err)
	}
	// A kernel redirect keeps the original source as the accepted peer.
	if _, err := TUNFlow(server, accepted.Source, destination); err == nil {
		t.Fatal("redirected TUN connection accepted")
	}
	if _, err := TUNFlow(server, source, netip.MustParseAddrPort("[2001:db8::2]:443")); err == nil {
		t.Fatal("mixed-family TUN tuple accepted")
	}
}
