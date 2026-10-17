package applicationhostname

import (
	"net"
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
