//go:build linux && sockowner_vm

package process

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/sys/unix"
)

// Pinned maps as a loader with conn_flows and an observer with
// wine_peer_flows publish them: the record of the exact flow is preferred.
// The source-keyed owner answers when there is none, but a source-keyed Wine
// record only when no destination is known: wine_egress writes both Wine
// records from the same packet, so a destination missing wine_peer_flows is
// another socket's, even if the Wine flow's last packet left wine_flows naming
// its program.
func TestFlowRecordsPreferred(t *testing.T) {
	dir := fmt.Sprintf("/sys/fs/bpf/mihomo-flow-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	create := func(name string, kind, keySize, valueSize, entries uint32) int {
		t.Helper()
		attr := struct{ Type, KeySize, ValueSize, MaxEntries uint32 }{kind, keySize, valueSize, entries}
		fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(int(fd)) })
		if err := pinObject(int(fd), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		return int(fd)
	}
	put := func(fd int, key, value unsafe.Pointer) {
		t.Helper()
		if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, fd, key, value); err != nil {
			t.Fatal(err)
		}
	}
	ownerKeySize, flowKeySize := uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(sockFlowKey{}))
	wineSize := uint32(unsafe.Sizeof(wineFlowValue{}))
	abi := create("abi_version", unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	owners := create("conn_owners", unix.BPF_MAP_TYPE_LRU_HASH, ownerKeySize, uint32(unsafe.Sizeof(sockOwnerValue{})), 16)
	cgroups := create(connCgroupsMap, unix.BPF_MAP_TYPE_LRU_HASH, ownerKeySize, uint32(unsafe.Sizeof(sockCgroupValue{})), 16)
	flows := create(connFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, flowKeySize, uint32(unsafe.Sizeof(sockFlowValue{})), 16)
	wineABI := create(wineABIMap, unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	heartbeat := create(wineHeartbeatMap, unix.BPF_MAP_TYPE_ARRAY, 4, 8, 1)
	wineFlowsFd := create(wineFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, ownerKeySize, wineSize, 16)
	winePeers := create(winePeerFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, flowKeySize, wineSize, 16)
	for slot, v := range []uint32{1, featureConnCgroups | featureConnFlows} {
		slot := uint32(slot)
		put(abi, unsafe.Pointer(&slot), unsafe.Pointer(&v))
	}
	for slot, v := range []uint32{wineABIVersion, wineFeaturePeerFlows} {
		slot := uint32(slot)
		put(wineABI, unsafe.Pointer(&slot), unsafe.Pointer(&v))
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	var slot uint32
	beat := uint64(now.Nano())
	put(heartbeat, unsafe.Pointer(&slot), unsafe.Pointer(&beat))

	source := netip.MustParseAddrPort("127.0.0.1:4300")
	librewolf, pasta := netip.MustParseAddrPort("198.18.0.5:443"), netip.MustParseAddrPort("198.18.0.9:443")
	key := ownerKey(t, "tcp", source)
	flowKey := func(peer netip.AddrPort) sockFlowKey {
		return flowKeys(key, []netip.AddrPort{peer})[0]
	}
	// conn_owners and conn_cgroups hold the relay, the last to send from the
	// port; conn_flows also has the browser's flow to its own destination.
	relayOwner := sockOwnerValue{Tgid: 111, UID: 1000, BootNs: 1}
	put(owners, unsafe.Pointer(&key), unsafe.Pointer(&relayOwner))
	relayCgroup := sockCgroupValue{Tgid: 111, BootNs: 1, CgroupID: 99}
	put(cgroups, unsafe.Pointer(&key), unsafe.Pointer(&relayCgroup))
	browser := sockFlowValue{Tgid: 222, UID: 1000, BootNs: 2, CgroupID: 77}
	k := flowKey(librewolf)
	put(flows, unsafe.Pointer(&k), unsafe.Pointer(&browser))
	alpha, beta := wineValue(`C:\Games\alpha.exe`), wineValue(`C:\Games\beta.exe`)
	// A relayed socket belongs to pasta, but its record names the sandbox's
	// wineserver and the Windows program, as the inner socket's does.
	for _, v := range []*wineFlowValue{alpha, beta} {
		v.Status, v.Protocol, v.ServerTgid, v.ClientTgid = wineStatusKnown, unix.IPPROTO_TCP, 333, 334
	}
	alpha.SocketID, beta.SocketID = 41, 42
	wineSockets := map[string]uint64{`C:\Games\alpha.exe`: 41, `C:\Games\beta.exe`: 42}
	put(wineFlowsFd, unsafe.Pointer(&key), unsafe.Pointer(alpha))
	k = flowKey(pasta)
	put(winePeers, unsafe.Pointer(&k), unsafe.Pointer(beta))

	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(dir, "conn_owners"))
	defer SetSockOwnerMap(previous)
	previousWine := wineFlowMaps
	wineFlowMaps = &wineFlows{flowsFd: -1, peerFlowsFd: -1, heartbeatFd: -1}
	defer func() { wineFlowMaps.closeLocked(); wineFlowMaps = previousWine }()

	for _, tc := range []struct {
		name  string
		peers []netip.AddrPort
		tgid  uint32
		wine  string
	}{
		// The browser's own flow has its own owner record, and no Wine
		// record for its destination: the relay's source-keyed one on the
		// same port is not the browser's.
		{"exact browser flow", []netip.AddrPort{librewolf}, 222, ""},
		// The relay's flow has its own Wine record.
		{"exact relay flow", []netip.AddrPort{pasta}, 111, `C:\Games\beta.exe`},
		// Any of the destinations a flow may carry finds its record.
		{"relay flow, second peer", []netip.AddrPort{netip.MustParseAddrPort("198.18.0.7:443"), pasta}, 111, `C:\Games\beta.exe`},
		// Without a destination, the source-only records apply.
		{"no destination", nil, 111, `C:\Games\alpha.exe`},
		{"invalid destination", []netip.AddrPort{{}}, 111, `C:\Games\alpha.exe`},
		// A destination with no record of either kind: the owner falls back
		// to conn_owners, but the Wine record names another socket's program.
		{"unknown destination", []netip.AddrPort{netip.MustParseAddrPort("198.18.0.7:443")}, 111, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, ok := lookupSockOwner("tcp", source.Addr(), int(source.Port()), tc.peers)
			if !ok || owner.Tgid != tc.tgid {
				t.Errorf("owner = %+v, %v; want TGID %d", owner, ok, tc.tgid)
			}
			_, path, ok := findWineProcess("tcp", source.Addr(), int(source.Port()), tc.peers)
			if path != tc.wine || ok != (tc.wine != "") {
				t.Errorf("Wine path = %q, %v; want %q", path, ok, tc.wine)
			}
			// The sender identity of UDP sessions reads the same records.
			id := FindFlowOwner("tcp", source.Addr(), int(source.Port()), tc.peers...)
			if id.Tgid != tc.tgid || id.WineSocket != wineSockets[tc.wine] {
				t.Errorf("flow owner = %+v; want TGID %d, Wine socket %d", id, tc.tgid, wineSockets[tc.wine])
			}
		})
	}
	if id, ok := lookupSockCgroup("tcp", source.Addr(), int(source.Port()), []netip.AddrPort{librewolf}); !ok || id != 77 {
		t.Errorf("cgroup = %d, %v; want the flow record's 77", id, ok)
	}
}

// A stale conn_flows record at the proxied or pre-redirect destination must not
// shadow the live record at the inbound listener for proxy and REDIR inbounds,
// while TUN and TPROXY still match PacketDst.
func TestFlowPeersStaleDstDoesNotShadowInbound(t *testing.T) {
	dir := fmt.Sprintf("/sys/fs/bpf/mihomo-flowpeers-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	create := func(name string, kind, keySize, valueSize, entries uint32) int {
		t.Helper()
		attr := struct{ Type, KeySize, ValueSize, MaxEntries uint32 }{kind, keySize, valueSize, entries}
		fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(int(fd)) })
		if err := pinObject(int(fd), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		return int(fd)
	}
	put := func(fd int, key, value unsafe.Pointer) {
		t.Helper()
		if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, fd, key, value); err != nil {
			t.Fatal(err)
		}
	}
	abi := create("abi_version", unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	create("conn_owners", unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(sockOwnerValue{})), 16)
	flows := create(connFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockFlowKey{})), uint32(unsafe.Sizeof(sockFlowValue{})), 16)
	for slot, v := range []uint32{1, featureConnFlows} {
		slot := uint32(slot)
		put(abi, unsafe.Pointer(&slot), unsafe.Pointer(&v))
	}

	source := netip.MustParseAddrPort("127.0.0.1:4301")
	packetDst := netip.MustParseAddrPort("1.1.1.1:443")
	inbound := netip.MustParseAddrPort("127.0.0.1:7890")
	key := ownerKey(t, "tcp", source)
	staleDst := sockFlowValue{Tgid: 111, UID: 1000, BootNs: 1}
	liveInbound := sockFlowValue{Tgid: 222, UID: 1000, BootNs: 2}
	kDst := flowKeys(key, []netip.AddrPort{packetDst})[0]
	kIn := flowKeys(key, []netip.AddrPort{inbound})[0]
	put(flows, unsafe.Pointer(&kDst), unsafe.Pointer(&staleDst))
	put(flows, unsafe.Pointer(&kIn), unsafe.Pointer(&liveInbound))

	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(dir, "conn_owners"))
	defer SetSockOwnerMap(previous)

	for _, tc := range []struct {
		name string
		typ  C.Type
		want uint32
	}{
		{"HTTP", C.HTTP, 222},
		{"SOCKS5", C.SOCKS5, 222},
		{"REDIR", C.REDIR, 222},
		{"TUN", C.TUN, 111},
		{"TPROXY", C.TPROXY, 111},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &C.Metadata{
				Type:      tc.typ,
				PacketDst: packetDst,
				InIP:      inbound.Addr(),
				InPort:    inbound.Port(),
			}
			owner, ok := lookupSockOwner("tcp", source.Addr(), int(source.Port()), m.FlowPeers())
			if !ok || owner.Tgid != tc.want {
				t.Fatalf("owner = %+v, ok=%v; want TGID %d", owner, ok, tc.want)
			}
		})
	}
}

// Once the pinned conn_owners map is removed or replaced, hits stop serving
// stale records from the detached map after the recheck interval.
func TestSockOwnerStopsServingDetachedMap(t *testing.T) {
	dir := fmt.Sprintf("/sys/fs/bpf/mihomo-detach-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	create := func(name string, kind, keySize, valueSize, entries uint32) int {
		t.Helper()
		attr := struct{ Type, KeySize, ValueSize, MaxEntries uint32 }{kind, keySize, valueSize, entries}
		fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(int(fd)) })
		if err := pinObject(int(fd), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		return int(fd)
	}
	abi := create("abi_version", unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	owners := create("conn_owners", unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(sockOwnerValue{})), 16)
	var slot uint32
	ver := uint32(1)
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, abi, unsafe.Pointer(&slot), unsafe.Pointer(&ver)); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("127.0.0.1:4302")
	key := ownerKey(t, "tcp", source)
	val := sockOwnerValue{Tgid: 333, UID: 1000, BootNs: 1}
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, owners, unsafe.Pointer(&key), unsafe.Pointer(&val)); err != nil {
		t.Fatal(err)
	}

	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(dir, "conn_owners"))
	defer SetSockOwnerMap(previous)

	if owner, ok := lookupSockOwner("tcp", source.Addr(), int(source.Port()), nil); !ok || owner.Tgid != 333 {
		t.Fatalf("before detach: owner = %+v, ok=%v; want TGID 333", owner, ok)
	}
	// Replace conn_owners with a new pinned map holding a different owner.
	if err := os.Remove(filepath.Join(dir, "conn_owners")); err != nil {
		t.Fatal(err)
	}
	owners2 := create("conn_owners", unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(sockOwnerValue{})), 16)
	val2 := sockOwnerValue{Tgid: 444, UID: 1000, BootNs: 2}
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, owners2, unsafe.Pointer(&key), unsafe.Pointer(&val2)); err != nil {
		t.Fatal(err)
	}
	sockOwners.mu.Lock()
	sockOwners.pinned.checkedAt = time.Now().Add(-sockOwnerRecheck - time.Millisecond)
	sockOwners.mu.Unlock()
	if owner, ok := lookupSockOwner("tcp", source.Addr(), int(source.Port()), nil); !ok || owner.Tgid != 444 {
		t.Fatalf("after replace: owner = %+v, ok=%v; want TGID 444", owner, ok)
	}
	// Remove conn_owners completely and verify hits stop serving stale records.
	if err := os.Remove(filepath.Join(dir, "conn_owners")); err != nil {
		t.Fatal(err)
	}
	sockOwners.mu.Lock()
	sockOwners.pinned.checkedAt = time.Now().Add(-sockOwnerRecheck - time.Millisecond)
	sockOwners.mu.Unlock()
	if owner, ok := lookupSockOwner("tcp", source.Addr(), int(source.Port()), nil); ok {
		t.Fatalf("after detach: still returned stale owner %+v", owner)
	}
}

// An exec-map record whose path failed to record (e.g. -ENAMETOOLONG) preserves
// the owner's UID and does not fall back to netlink/proc lookup.
func TestExecPathErrorPreservesUIDWithoutFallback(t *testing.T) {
	dir := fmt.Sprintf("/sys/fs/bpf/mihomo-execerr-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	create := func(name string, kind, keySize, valueSize, entries uint32) int {
		t.Helper()
		attr := struct{ Type, KeySize, ValueSize, MaxEntries uint32 }{kind, keySize, valueSize, entries}
		fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(int(fd)) })
		if err := pinObject(int(fd), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		return int(fd)
	}
	abi := create("abi_version", unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	owners := create("conn_owners", unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(sockOwnerValue{})), 16)
	recent := create(execRecentMap, unix.BPF_MAP_TYPE_LRU_HASH, 4, uint32(unsafe.Sizeof(execPathValue{})), 16)
	var slot uint32
	ver := uint32(1)
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, abi, unsafe.Pointer(&slot), unsafe.Pointer(&ver)); err != nil {
		t.Fatal(err)
	}

	source := netip.MustParseAddrPort("127.0.0.1:4303")
	key := ownerKey(t, "tcp", source)
	ownerVal := sockOwnerValue{Tgid: 999999, UID: 2345, BootNs: 100}
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, owners, unsafe.Pointer(&key), unsafe.Pointer(&ownerVal)); err != nil {
		t.Fatal(err)
	}
	tgid := uint32(999999)
	execVal := execPathValue{StartNs: 50, ExitNs: 0, Len: -int32(unix.ENAMETOOLONG)}
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, recent, unsafe.Pointer(&tgid), unsafe.Pointer(&execVal)); err != nil {
		t.Fatal(err)
	}

	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(dir, "conn_owners"))
	defer SetSockOwnerMap(previous)
	prevOnly := SockOwnerOnly()
	SetSockOwnerOnly(false)
	defer SetSockOwnerOnly(prevOnly)

	// Open conn_owners, then attach exec_recent directly (TASK_STORAGE needs BTF
	// to create without the loader, and PID 999999 falls through to exec_recent).
	sockOwners.lookup(func(int, uint64) bool { return false })
	dupTasks, err := unix.FcntlInt(uintptr(recent), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dupRecent, err := unix.FcntlInt(uintptr(recent), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		unix.Close(dupTasks)
		t.Fatal(err)
	}
	sockOwners.mu.Lock()
	sockOwners.tasksFd = dupTasks
	sockOwners.recentFd = dupRecent
	sockOwners.mu.Unlock()

	beforeFallbacks := lookupCounters.procFallbacks.Load()
	uid, path, err := findProcessNameTo("tcp", source.Addr(), int(source.Port()), nil)
	if uid != 2345 || path != "" || err == nil {
		t.Fatalf("got uid=%d path=%q err=%v; want uid=2345, empty path, error", uid, path, err)
	}
	if lookupCounters.procFallbacks.Load() != beforeFallbacks {
		t.Fatalf("fell back to /proc on -ENAMETOOLONG exec record")
	}
}
