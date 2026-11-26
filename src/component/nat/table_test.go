package nat

import (
	"net"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type testSender struct {
	C.PacketSender
	name string
}

// A sender replacing another on the same address keeps its local conns, and
// the replaced sender's teardown leaves them and the entry alone.
func TestReplaceKeepsLocalConns(t *testing.T) {
	table := New()
	alpha, beta := &testSender{name: "alpha"}, &testSender{name: "beta"}
	if got, loaded := table.GetOrCreate("lAddr", func() C.PacketSender { return alpha }); loaded || got != alpha {
		t.Fatalf("GetOrCreate = %v, %v", got, loaded)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !table.AddForLocalConn("lAddr", "rAddr", conn) {
		t.Fatal("no entry for the local conn")
	}

	got, created := table.Replace("lAddr", alpha, func() C.PacketSender { return beta })
	if !created || got != beta {
		t.Fatalf("Replace = %v, %v; want beta, created", got, created)
	}
	// alpha was replaced already: a second replacement of it does nothing.
	if got, created := table.Replace("lAddr", alpha, func() C.PacketSender { return &testSender{} }); created || got != beta {
		t.Fatalf("stale Replace = %v, %v; want beta", got, created)
	}
	if table.GetForLocalConn("lAddr", "rAddr") != conn {
		t.Error("the replacement lost the local conn")
	}
	if table.DeleteFor("lAddr", alpha, func(string, *net.UDPConn) bool { t.Error("closed beta's local conn"); return true }) {
		t.Error("the replaced sender deleted the entry")
	}
	if got, loaded := table.GetOrCreate("lAddr", func() C.PacketSender { return alpha }); !loaded || got != beta {
		t.Errorf("entry = %v, %v; want beta", got, loaded)
	}

	var closed []string
	if !table.DeleteFor("lAddr", beta, func(rAddr string, _ *net.UDPConn) bool { closed = append(closed, rAddr); return true }) {
		t.Fatal("the current sender didn't delete its entry")
	}
	if len(closed) != 1 || closed[0] != "rAddr" {
		t.Errorf("local conns passed on delete: %v", closed)
	}
	if table.GetForLocalConn("lAddr", "rAddr") != nil {
		t.Error("entry still present")
	}
	// Replacing a sender whose entry is gone creates one.
	if got, created := table.Replace("lAddr", beta, func() C.PacketSender { return alpha }); !created || got != alpha {
		t.Errorf("Replace after delete = %v, %v", got, created)
	}
}
