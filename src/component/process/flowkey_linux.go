package process

import (
	"net/netip"
	"path/filepath"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

// conn_flows keys socket owners by destination as well as source, so that
// sockets sharing a local address and port, which connect() allows for
// different peers, keep their own records (docs/socketowner.md).
const (
	connFlowsMap     = "conn_flows"
	featureConnFlows = 1 << 2
)

// sockFlowKey is the conn_flows key: the outgoing packet's addresses and
// ports. IPv4 addresses are IPv4-mapped.
type sockFlowKey struct {
	Netns uint64
	Saddr [16]byte
	Daddr [16]byte
	Sport uint16
	Dport uint16
	Proto uint8
	_     [3]byte
}

// sockFlowValue is a conn_flows record: the owner, as in conn_owners, and its
// cgroup, written together.
type sockFlowValue struct {
	Tgid     uint32
	UID      uint32
	BootNs   uint64
	CgroupID uint64
}

func (v *sockFlowValue) owner() sockOwnerValue {
	return sockOwnerValue{Tgid: v.Tgid, UID: v.UID, BootNs: v.BootNs}
}

// flowKeys returns the conn_flows keys of a connection for each destination
// its outgoing packets may carry, skipping invalid and repeated ones.
func flowKeys(key sockOwnerKey, peers []netip.AddrPort) []sockFlowKey {
	keys := make([]sockFlowKey, 0, len(peers))
	for _, peer := range peers {
		addr := peer.Addr().Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || peer.Port() == 0 {
			continue
		}
		k := sockFlowKey{Netns: key.Netns, Saddr: key.Addr, Daddr: addr.As16(),
			Sport: key.Port, Dport: peer.Port(), Proto: key.Proto}
		duplicate := false
		for _, seen := range keys {
			duplicate = duplicate || seen == k
		}
		if !duplicate {
			keys = append(keys, k)
		}
	}
	return keys
}

// openFlowMapLocked opens conn_flows beside the open socket-owner map when
// the loader advertises it. Without it, lookups use conn_owners alone.
func (m *sockOwnerMap) openFlowMapLocked() {
	if m.features&featureConnFlows == 0 {
		return
	}
	fd, err := openBPFMap(filepath.Join(filepath.Dir(m.path), connFlowsMap), unix.BPF_MAP_TYPE_LRU_HASH,
		uint32(unsafe.Sizeof(sockFlowKey{})), sockFlowValue{})
	if err != nil {
		if m.pinned.warnOnce(err) {
			log.Warnln("[Process] Can't tell apart connections sharing a source port: %v", err)
		}
		return
	}
	m.flowsFd = fd
}

// lookupFlowLocked returns the conn_flows record of a connection to one of
// peers, with m.mu held for reading. key carries the namespace.
func (m *sockOwnerMap) lookupFlowLocked(key sockOwnerKey, peers []netip.AddrPort) (sockFlowValue, bool) {
	var value sockFlowValue
	if m.flowsFd < 0 {
		return value, false
	}
	for _, k := range flowKeys(key, peers) {
		if lookupBPFMap(m.flowsFd, &k, &value) {
			return value, true
		}
	}
	return value, false
}

func findFlowOwner(network string, ip netip.Addr, srcPort int, peers []netip.AddrPort) FlowOwner {
	key, ok := newSockOwnerKey(network, ip, srcPort)
	if !ok {
		return FlowOwner{}
	}
	var id FlowOwner
	var owner sockOwnerValue
	if sockOwners.lookup(func(fd int, netns uint64) bool {
		k := key
		k.Netns = netns
		if flow, ok := sockOwners.lookupFlowLocked(k, peers); ok {
			owner = flow.owner()
			return true
		}
		return lookupBPFMap(fd, &k, &owner)
	}) {
		id.Tgid, id.UID, id.BootNs = owner.Tgid, owner.UID, owner.BootNs
	}
	sockOwners.mu.RLock()
	dir, enabled := wineFlowsDir(sockOwners.path)
	sockOwners.mu.RUnlock()
	if !enabled {
		return id
	}
	if wine, ok := wineFlowMaps.record(&key, peers, dir); ok {
		id.WineSocket, id.WineServer, id.WineClient, id.WineStatus = wine.SocketID, wine.ServerTgid, wine.ClientTgid, wine.Status
	}
	return id
}
