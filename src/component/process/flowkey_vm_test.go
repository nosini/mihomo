//go:build linux && sockowner_vm

package process

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Pinned maps as a loader with conn_flows and an observer with
// wine_peer_flows publish them: a record of the exact flow is preferred, and
// a source-only Wine record of another owner is not taken for the flow's.
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
	flows := create(connFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, flowKeySize, uint32(unsafe.Sizeof(sockFlowValue{})), 16)
	wineABI := create(wineABIMap, unix.BPF_MAP_TYPE_ARRAY, 4, 4, 2)
	heartbeat := create(wineHeartbeatMap, unix.BPF_MAP_TYPE_ARRAY, 4, 8, 1)
	wineFlowsFd := create(wineFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, ownerKeySize, wineSize, 16)
	winePeers := create(winePeerFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, flowKeySize, wineSize, 16)
	for slot, v := range []uint32{1, featureConnFlows} {
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
	// conn_owners holds the relay, the last to send from the port; conn_flows
	// also has the browser's flow to its own destination.
	relayOwner := sockOwnerValue{Tgid: 111, UID: 1000, BootNs: 1}
	put(owners, unsafe.Pointer(&key), unsafe.Pointer(&relayOwner))
	browser := sockFlowValue{Tgid: 222, UID: 1000, BootNs: 2, CgroupID: 77}
	k := flowKey(librewolf)
	put(flows, unsafe.Pointer(&k), unsafe.Pointer(&browser))
	alpha, beta := wineValue(`C:\Games\alpha.exe`), wineValue(`C:\Games\beta.exe`)
	for _, v := range []*wineFlowValue{alpha, beta} {
		v.Status, v.Protocol, v.ServerTgid = wineStatusKnown, unix.IPPROTO_TCP, relayOwner.Tgid
	}
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
		// The browser's own flow: its record, and the relay's Wine record
		// on the same port is someone else's.
		{"exact browser flow", []netip.AddrPort{librewolf}, 222, ""},
		// The relay's flow has its own Wine record.
		{"exact relay flow", []netip.AddrPort{pasta}, 111, `C:\Games\beta.exe`},
		// Without a destination, the source-only records apply.
		{"no destination", nil, 111, `C:\Games\alpha.exe`},
		{"unknown destination", []netip.AddrPort{netip.MustParseAddrPort("198.18.0.7:443")}, 111, `C:\Games\alpha.exe`},
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
		})
	}
	if id, ok := lookupSockCgroup("tcp", source.Addr(), int(source.Port()), []netip.AddrPort{librewolf}); !ok || id != 77 {
		t.Errorf("cgroup = %d, %v; want the flow record's 77", id, ok)
	}
}
