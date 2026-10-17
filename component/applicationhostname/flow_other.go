//go:build !linux || !amd64

package applicationhostname

import "net"

func AcceptedFlow(net.Conn) (Flow, error) { return Flow{}, ErrUnavailable }
