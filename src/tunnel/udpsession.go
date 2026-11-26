package tunnel

import (
	"sync"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

// udpSession is a UDP NAT session, keyed by its source address and port alone,
// with the recorded sender of the packet that opened it. Its route was chosen
// for that sender: a packet from another sender on the same address and port,
// such as a process that reused the port or shares it, starts a new session
// with its own rule match, rather than leaving through this one's outbound.
type udpSession struct {
	C.PacketSender
	owner process.FlowOwner

	mu     sync.Mutex
	pc     C.PacketConn
	closed bool
}

// findFlowOwner is replaced in tests.
var findFlowOwner = process.FindFlowOwner

// udpFlowOwner returns the recorded sender of a packet when the route can
// depend on it: process lookup is on and rules choose the route.
func udpFlowOwner(metadata *C.Metadata) process.FlowOwner {
	if features.CMFA || metadata.Type == C.INNER || metadata.SpecialProxy != "" ||
		mode != Rule || FindProcessMode() == process.FindProcessOff {
		return process.FlowOwner{}
	}
	return findFlowOwner(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort), metadata.FlowPeers()...)
}

func newUDPSession(sender C.PacketSender, owner process.FlowOwner) *udpSession {
	return &udpSession{PacketSender: sender, owner: owner}
}

// attach records the session's outbound connection. It returns false when the
// session was closed first, by another sender's session replacing it; the
// caller then closes pc.
func (s *udpSession) attach(pc C.PacketConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.pc = pc
	return true
}

// isClosed reports whether the session was closed, by another sender's
// session replacing it.
func (s *udpSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops the session's sender and closes its outbound connection, which
// ends the goroutine writing replies back.
func (s *udpSession) Close() {
	s.PacketSender.Close()
	s.mu.Lock()
	s.closed = true
	pc := s.pc
	s.pc = nil
	s.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}
