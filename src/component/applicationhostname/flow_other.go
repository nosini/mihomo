//go:build !linux || !amd64

package applicationhostname

import (
	"net"
	"net/netip"
)

func AcceptedFlow(net.Conn) (Flow, error) { return Flow{}, ErrUnavailable }

func TUNFlow(net.Conn, netip.AddrPort, netip.AddrPort) (Flow, error) { return Flow{}, ErrUnavailable }
