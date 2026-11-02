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

	"golang.org/x/sys/unix"
)

// Real pinned maps exercise the production reader's stale-record behavior:
// stale positive records must remain WineUnknown rather than fall through to pasta.
func TestWineFlowStalePublisher(t *testing.T) {
	dir := fmt.Sprintf("/sys/fs/bpf/mihomo-wine-test-%d", os.Getpid())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	create := func(name string, kind, keySize, valueSize uint32) int {
		t.Helper()
		attr := struct{ Type, KeySize, ValueSize, MaxEntries uint32 }{kind, keySize, valueSize, 1}
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
	version := create(wineABIMap, unix.BPF_MAP_TYPE_ARRAY, 4, 4)
	heartbeat := create(wineHeartbeatMap, unix.BPF_MAP_TYPE_ARRAY, 4, 8)
	flows := create(wineFlowsMap, unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), uint32(unsafe.Sizeof(wineFlowValue{})))
	put := func(fd int, key, value unsafe.Pointer) {
		t.Helper()
		if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, fd, key, value); err != nil {
			t.Fatal(err)
		}
	}
	var slot uint32
	abi := wineABIVersion
	put(version, unsafe.Pointer(&slot), unsafe.Pointer(&abi))
	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(dir, "conn_owners"))
	defer SetSockOwnerMap(previous)
	// The global optional reader keeps FDs between calls; restore it too.
	previousWine := wineFlowMaps
	wineFlowMaps = &wineFlows{flowsFd: -1, heartbeatFd: -1}
	defer func() { wineFlowMaps.closeLocked(); wineFlowMaps = previousWine }()
	key := ownerKey(t, "tcp", netip.MustParseAddrPort("127.0.0.1:4255"))
	value := wineValue(`C:\Games\alpha.exe`)
	value.Status, value.Protocol, value.UID = wineStatusKnown, unix.IPPROTO_TCP, 1000
	put(flows, unsafe.Pointer(&key), unsafe.Pointer(value))
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	beat := uint64(now.Nano())
	put(heartbeat, unsafe.Pointer(&slot), unsafe.Pointer(&beat))
	check := func(want string, covered bool) {
		t.Helper()
		uid, path, ok := lookupWineFlow("tcp", netip.MustParseAddr("127.0.0.1"), 4255)
		if path != want || ok != covered || (ok && uid != value.UID) {
			t.Fatalf("got uid=%d path=%q covered=%v; want %q covered=%v", uid, path, ok, want, covered)
		}
	}
	check(`C:\Games\alpha.exe`, true)
	beat = uint64(now.Nano() - int64(wineHeartbeatLimit) - int64(time.Second))
	put(heartbeat, unsafe.Pointer(&slot), unsafe.Pointer(&beat))
	check(WineUnknown, true)
	// A fresh beat makes the retained record readable again.
	beat = uint64(now.Nano())
	put(heartbeat, unsafe.Pointer(&slot), unsafe.Pointer(&beat))
	check(`C:\Games\alpha.exe`, true)
	value.Status = 7
	put(flows, unsafe.Pointer(&key), unsafe.Pointer(value))
	check(WineUnknown, true)
	if err := mapElem(unix.BPF_MAP_DELETE_ELEM, flows, unsafe.Pointer(&key), nil); err != nil {
		t.Fatal(err)
	}
	check("", false)
}
