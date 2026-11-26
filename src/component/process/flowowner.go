package process

import "net/netip"

// FlowOwner identifies the sender of a connection's packets as far as the
// socket-owner maps record it: the process using the socket, and for a Wine
// flow the Windows program's socket. A record keeps its values while one
// process uses one socket, so a different value means the packets now come
// from another process or Windows socket, such as one that reused the source
// port. The zero value means nothing is recorded.
type FlowOwner struct {
	Tgid   uint32
	UID    uint32
	BootNs uint64

	WineSocket uint64
	WineServer uint32
	WineClient uint32
	WineStatus uint32
}

// FindFlowOwner returns the recorded sender of a connection's packets. peers
// are the destinations its packets may carry, as for FindProcessName. It reads
// the maps only, never /proc, and is not counted in the lookup health, so it
// can be called for every packet.
func FindFlowOwner(network string, srcIP netip.Addr, srcPort int, peers ...netip.AddrPort) FlowOwner {
	return findFlowOwner(network, srcIP, srcPort, peers)
}
