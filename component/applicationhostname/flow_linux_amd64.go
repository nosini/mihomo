package applicationhostname

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// AcceptedFlow reads identity from the accepted socket, never from process
// lookup or a namespace-wide source-only owner key. Wrapper traversal is bounded.
func AcceptedFlow(conn net.Conn) (Flow, error) {
	source, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return Flow{}, err
	}
	destination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return Flow{}, err
	}
	var value any = conn
	for i := 0; i < 16; i++ {
		if socket, ok := value.(syscall.Conn); ok {
			raw, err := socket.SyscallConn()
			if err != nil {
				return Flow{}, err
			}
			var ns uint64
			var sockErr error
			err = raw.Control(func(fd uintptr) { ns, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, 71) }) // SO_NETNS_COOKIE
			if err != nil || sockErr != nil || ns == 0 {
				return Flow{}, ErrUnavailable
			}
			return Flow{Netns: ns, Source: netip.AddrPortFrom(source.Addr().Unmap(), source.Port()), Destination: netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())}, nil
		}
		wrapper, ok := value.(interface{ Upstream() any })
		if !ok {
			break
		}
		value = wrapper.Upstream()
	}
	return Flow{}, ErrUnavailable
}

// TUNFlow returns the flow for a TCP connection from the TUN system stack. The
// stack accepts its own kernel socket in the TUN device's network namespace and
// reports the application's original tuple from its NAT table; the observer
// keyed the application socket's egress by that tuple in the same namespace.
// A socket whose peer is the original source arrived through a kernel redirect
// (auto-redirect) instead, which is not supported.
func TUNFlow(conn net.Conn, source, destination netip.AddrPort) (Flow, error) {
	accepted, err := AcceptedFlow(conn)
	if err != nil {
		return Flow{}, err
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if accepted.Source == source || source.Addr().Is4() != destination.Addr().Is4() {
		return Flow{}, ErrUnavailable
	}
	return Flow{Netns: accepted.Netns, Source: source, Destination: destination}, nil
}
