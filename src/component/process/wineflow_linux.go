package process

import (
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"
)

// WineUnknown is the process name of a flow relayed for a Wine sandbox whose
// Windows program could not be established. It is distinct from the relay's
// own name so that rules can refuse it: a deny for one Windows program must
// not be passed just because that program's identity was unavailable.
const WineUnknown = "wine-unknown"

// The optional Windows identity maps from socketowner's wine,
// pinned beside conn_owners with their own version.
const (
	wineFlowsMap     = "wine_flows"
	wineABIMap       = "wine_abi"
	wineHeartbeatMap = "wine_heartbeat"
	wineABIVersion   = uint32(2)
	wineImageBytes   = 1024
	wineStatusKnown  = 1
	// The publisher writes its heartbeat every second.
	wineHeartbeatLimit = 5 * time.Second
)

type wineFlowValue struct {
	SocketID       uint64
	ServerStartNs  uint64
	ClientStartNs  uint64
	CapturedBootNs uint64
	ServerTgid     uint32
	UID            uint32
	WindowsPID     uint32
	ClientTgid     uint32
	Status         uint32
	ImageBytes     uint32
	Protocol       uint32
	Encoding       uint32
	Image          [wineImageBytes / 2]uint16
}

// wineFlows opens its maps as sockOwners does, separately: they come and go
// with one sandbox's publisher, not with the socketowner loader. netns is
// mihomo's network namespace cookie, which keys the records as in conn_owners.
type wineFlows struct {
	mu          sync.RWMutex
	flowsFd     int
	heartbeatFd int
	ino         uint64
	netns       uint64
	checkedAt   time.Time
}

var wineFlowMaps = &wineFlows{flowsFd: -1, heartbeatFd: -1}

func (w *wineFlows) closeLocked() {
	for _, fd := range []*int{&w.flowsFd, &w.heartbeatFd} {
		if *fd >= 0 {
			unix.Close(*fd)
			*fd = -1
		}
	}
}

func (w *wineFlows) refreshLocked(dir string) {
	w.checkedAt = time.Now()
	if dir == "." {
		w.closeLocked()
		return
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(dir, wineFlowsMap), &st); err != nil {
		w.closeLocked()
		return
	}
	if w.flowsFd >= 0 && st.Ino == w.ino {
		return
	}
	w.closeLocked()
	version, err := openBPFMap(filepath.Join(dir, wineABIMap), unix.BPF_MAP_TYPE_ARRAY, 4, uint32(0))
	if err != nil {
		return
	}
	defer unix.Close(version)
	var key, abi uint32
	if !lookupBPFMap(version, &key, &abi) || abi != wineABIVersion {
		return
	}
	netns, err := currentNetnsCookie()
	if err != nil {
		return
	}
	heartbeat, err := openBPFMap(filepath.Join(dir, wineHeartbeatMap), unix.BPF_MAP_TYPE_ARRAY, 4, uint64(0))
	if err != nil {
		return
	}
	flows, err := openBPFMap(filepath.Join(dir, wineFlowsMap), unix.BPF_MAP_TYPE_LRU_HASH,
		uint32(unsafe.Sizeof(sockOwnerKey{})), wineFlowValue{})
	if err != nil {
		unix.Close(heartbeat)
		return
	}
	w.flowsFd, w.heartbeatFd, w.ino, w.netns = flows, heartbeat, st.Ino, netns
}

// lookup returns the record of a flow, given its key without the namespace.
// live is false if its publisher stopped beating, which leaves records
// unmaintained: a port may have changed hands.
func (w *wineFlows) lookup(key *sockOwnerKey, dir string) (value wineFlowValue, live, found bool) {
	w.mu.RLock()
	stale := time.Since(w.checkedAt) >= sockOwnerMissRecheck
	w.mu.RUnlock()
	if stale {
		w.mu.Lock()
		if time.Since(w.checkedAt) >= sockOwnerMissRecheck {
			w.refreshLocked(dir)
		}
		w.mu.Unlock()
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.flowsFd < 0 {
		return value, false, false
	}
	key.Netns = w.netns
	if !lookupBPFMap(w.flowsFd, key, &value) {
		return value, false, false
	}
	var slot uint32
	var beat uint64
	var now unix.Timespec
	if lookupBPFMap(w.heartbeatFd, &slot, &beat) && unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) == nil {
		live = now.Nano()-int64(beat) < int64(wineHeartbeatLimit)
	}
	return value, live, true
}

// findWineProcess names the Windows program behind a flow, which is reported
// beside the process owning the socket, such as a sandbox's relay. ok is false
// when no Wine record covers it. An unusable record gives WineUnknown, so that
// a rule for a Windows program is never passed for lack of its identity.
func findWineProcess(network string, ip netip.Addr, srcPort int) (name, path string, ok bool) {
	key := sockOwnerKey{Addr: ip.Unmap().As16(), Port: uint16(srcPort)}
	switch {
	case strings.HasPrefix(network, "tcp"):
		key.Proto = unix.IPPROTO_TCP
	case strings.HasPrefix(network, "udp"):
		key.Proto = unix.IPPROTO_UDP
	default:
		return "", "", false
	}
	sockOwners.mu.RLock()
	dir := filepath.Dir(sockOwners.path)
	sockOwners.mu.RUnlock()
	value, live, found := wineFlowMaps.lookup(&key, dir)
	if !found {
		return "", "", false
	}
	if !live || value.Status != wineStatusKnown || uint32(key.Proto) != value.Protocol {
		return WineUnknown, WineUnknown, true
	}
	if name, path, ok = wineImage(&value); !ok {
		return WineUnknown, WineUnknown, true
	}
	return name, path, true
}

// wineImage decodes the image as socketowner does: an absolute UTF-16 Windows
// drive or UNC path, or the filename alone in bytes for clients with no
// reachable path. socketowner published it only after checking it; a reader of
// a shared ABI checks again, so that a malformed image is never a usable name.
func wineImage(value *wineFlowValue) (name, path string, ok bool) {
	size := value.ImageBytes
	if value.Encoding == 1 {
		if size == 0 || size > wineImageBytes {
			return "", "", false
		}
		raw := make([]byte, 0, size+1)
		for _, w := range value.Image[:(size+1)/2] {
			raw = append(raw, byte(w), byte(w>>8))
		}
		name = string(raw[:size])
		if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00/\\") || name == "." || name == ".." {
			return "", "", false
		}
		return name, name, true
	}
	if value.Encoding != 0 || size < 2 || size > wineImageBytes || size%2 != 0 {
		return "", "", false
	}
	w := value.Image[:size/2]
	for i := 0; i < len(w); i++ {
		switch c := w[i]; {
		case c == 0:
			return "", "", false
		case c >= 0xd800 && c <= 0xdbff:
			if i+1 == len(w) || w[i+1] < 0xdc00 || w[i+1] > 0xdfff {
				return "", "", false
			}
			i++
		case c >= 0xdc00 && c <= 0xdfff:
			return "", "", false
		}
	}
	path = strings.ReplaceAll(string(utf16.Decode(w)), "/", `\`)
	path = strings.TrimPrefix(strings.TrimPrefix(path, `\??\`), `\\?\`)
	if strings.HasPrefix(path, `UNC\`) {
		path = `\\` + path[4:]
	}
	drive := len(path) >= 3 && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') && path[1:3] == `:\`
	unc := false
	if strings.HasPrefix(path, `\\`) {
		parts := strings.Split(path[2:], `\`)
		unc = len(parts) >= 3 && parts[0] != "" && parts[1] != ""
	}
	if !drive && !unc {
		return "", "", false
	}
	name = path[strings.LastIndexByte(path, '\\')+1:]
	if name == "" || name == "." || name == ".." {
		return "", "", false
	}
	return name, path, true
}
