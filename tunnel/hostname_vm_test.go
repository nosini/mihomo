//go:build linux && amd64 && hostname_vm

package tunnel_test

// This test-only bridge runs the real REDIRECT listener and TCP tunnel. Its
// inherited socket speaks only to the supervising socketowner VM test, which
// owns all BPF maps and links. This is not an external hostname service ABI.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/redir"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules/common"
	T "github.com/metacubex/mihomo/tunnel"
	"golang.org/x/sys/unix"
)

type hostnameVMEvent struct {
	Kind, Address, Source, Local, Original, Name, Proxy, Host string
	Netns, Cookie                                             uint64
	ElapsedNS                                                 int64
}

type hostnameVMReply struct {
	Name string
}

type hostnameVMControl struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	mu   sync.Mutex
}

func (c *hostnameVMControl) event(e hostnameVMEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Event reporting has its own test timeout; it is outside the lookup budget.
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.enc.Encode(e)
}

func (c *hostnameVMControl) exchange(e hostnameVMEvent, deadline time.Time) (hostnameVMReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})
	var reply hostnameVMReply
	if err := c.enc.Encode(e); err != nil {
		return reply, err
	}
	err := c.dec.Decode(&reply)
	return reply, err
}

// Keep experiment evidence separate from Host/SniffHost and expose it only to
// this ordinary DOMAIN rule's cloned metadata. The original dial metadata is
// never changed. Production provenance and precedence remain to be designed.
type hostnameVMRule struct {
	C.Rule
	name *string
}

func (r hostnameVMRule) Match(m *C.Metadata, h C.RuleMatchHelper) (bool, string) {
	if *r.name == "" {
		return false, r.Adapter()
	}
	copy := m.Clone()
	copy.Host, copy.SniffHost = *r.name, ""
	return r.Rule.Match(copy, h)
}

type hostnameVMProxy struct {
	*outbound.Direct
	control *hostnameVMControl
	start   *time.Time
}

func (p *hostnameVMProxy) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	if err := p.control.event(hostnameVMEvent{Kind: "dial", Proxy: p.Name(), Original: m.RemoteAddress(), Host: m.Host, ElapsedNS: time.Since(*p.start).Nanoseconds()}); err != nil {
		return nil, err
	}
	conn, err := p.Direct.DialContext(ctx, m)
	if err != nil {
		p.control.event(hostnameVMEvent{Kind: "dial-error", Name: err.Error()})
	} else if reportErr := p.control.event(hostnameVMEvent{Kind: "connected"}); reportErr != nil {
		conn.Close()
		return nil, reportErr
	}
	return conn, err
}

type hostnameVMTunnel struct {
	C.Tunnel
	control *hostnameVMControl
	budget  time.Duration
	name    *string
	start   *time.Time
	done    chan struct{}
}

func (h *hostnameVMTunnel) HandleTCPConn(conn net.Conn, m *C.Metadata) {
	defer close(h.done) // one inbound per helper process
	defer conn.Close()
	e := hostnameVMEvent{Kind: "accepted", Source: conn.RemoteAddr().String(), Local: conn.LocalAddr().String(), Original: m.RemoteAddress()}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		e.Netns, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		if sockErr == nil {
			e.Cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		}
	})
	if err != nil || sockErr != nil {
		return
	}
	// Let the parent verify the accepted tuple before releasing routing.
	if _, err := h.control.exchange(e, time.Now().Add(5*time.Second)); err != nil {
		return
	}
	*h.start = time.Now()
	deadline := h.start.Add(h.budget)
	for h.budget > 0 && time.Now().Before(deadline) {
		reply, err := h.control.exchange(hostnameVMEvent{Kind: "lookup"}, deadline)
		if err != nil || !time.Now().Before(deadline) {
			break // unknown on failure or a response outside the budget
		}
		if reply.Name != "" {
			*h.name = reply.Name
			break
		}
		time.Sleep(time.Millisecond)
	}
	h.Tunnel.HandleTCPConn(conn, m)
}

func TestVMHostnameRouteHelper(t *testing.T) {
	if os.Getenv("HOSTNAME_VM_ROUTE_HELPER") != "1" {
		t.Skip("launched only by socketowner's supervised VM experiment")
	}
	file := os.NewFile(3, "hostname-test-control")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	control := &hostnameVMControl{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}
	budget, err := strconv.Atoi(os.Getenv("HOSTNAME_VM_ROUTE_BUDGET_MS"))
	if err != nil || budget < 0 || budget > 1000 {
		t.Fatal("invalid experiment budget")
	}
	T.SetFindProcessMode(process.FindProcessOff)
	if os.Getenv("HOSTNAME_VM_ROUTE_PROCESS") == "always" {
		T.SetFindProcessMode(process.FindProcessAlways)
	}
	log.SetLevel(log.SILENT)
	resolver.DisableIPv6 = false
	T.OnRunning()
	var name string
	var start time.Time
	proxies := make(map[string]C.Proxy)
	for _, name := range []string{"NAMED", "DIRECT"} {
		p := &hostnameVMProxy{Direct: outbound.NewDirectWithOption(outbound.DirectOption{Name: name}), control: control, start: &start}
		proxies[name] = adapter.NewProxy(p)
	}
	T.UpdateProxies(proxies, nil)
	T.UpdateRules([]C.Rule{hostnameVMRule{Rule: R.NewDomain("route.invalid", "NAMED"), name: &name}}, nil, nil)
	h := &hostnameVMTunnel{Tunnel: T.Tunnel, control: control, budget: time.Duration(budget) * time.Millisecond, name: &name, start: &start, done: make(chan struct{})}
	listener, err := redir.New(os.Getenv("HOSTNAME_VM_ROUTE_LISTEN"), h)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := control.event(hostnameVMEvent{Kind: "ready", Address: listener.Address()}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		t.Fatal(fmt.Errorf("supervised route experiment did not finish"))
	}
}
