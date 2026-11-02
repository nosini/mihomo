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

// The optional Windows identity maps from socketowner's experiments/wine,
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
	SocketID         uint64
	ServerStartNs    uint64
	ClientStartNs    uint64
	CapturedBootNs   uint64
	ServerTgid       uint32
	UID              uint32
	WindowsPID       uint32
	ClientTgid       uint32
	Status           uint32
	ImageBytes       uint32
	Protocol         uint32
	Encoding         uint32
	Image            [wineImageBytes / 2]uint16
}

// wineFlows opens its maps as sockOwners does, separately: they come and go
// with one sandbox's publisher, not with the socketowner loader.
type wineFlows struct {
	mu          sync.RWMutex
	flowsFd     int
	heartbeatFd int
	ino         uint64
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
	w.flowsFd, w.heartbeatFd, w.ino = flows, heartbeat, st.Ino
}

// lookup returns the record of a flow. live is false if its publisher stopped
// beating, which leaves records unmaintained: a port may have changed hands.
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
	if w.flowsFd < 0 || !lookupBPFMap(w.flowsFd, key, &value) {
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

// lookupWineFlow names the Windows program behind a flow. ok is false when no
// Wine record covers it, and ordinary lookup should proceed. An unusable record
// gives WineUnknown; falling through would report the relay or a reused port's
// owner.
func lookupWineFlow(network string, ip netip.Addr, srcPort int) (uid uint32, path string, ok bool) {
	key := sockOwnerKey{Addr: ip.Unmap().As16(), Port: uint16(srcPort)}
	switch {
	case strings.HasPrefix(network, "tcp"):
		key.Proto = unix.IPPROTO_TCP
	case strings.HasPrefix(network, "udp"):
		key.Proto = unix.IPPROTO_UDP
	default:
		return 0, "", false
	}
	sockOwners.mu.RLock()
	dir, netns := filepath.Dir(sockOwners.path), sockOwners.netns
	sockOwners.mu.RUnlock()
	if netns == 0 {
		// conn_owners has not been opened yet, which supplies the cookie.
		var err error
		if netns, err = currentNetnsCookie(); err != nil {
			return 0, "", false
		}
	}
	key.Netns = netns
	value, live, found := wineFlowMaps.lookup(&key, dir)
	if !found {
		return 0, "", false
	}
	if !live || value.Status != wineStatusKnown || uint32(key.Proto) != value.Protocol {
		return value.UID, WineUnknown, true
	}
	image, ok := wineImagePath(&value)
	if !ok {
		return value.UID, WineUnknown, true
	}
	return value.UID, image, true
}

// wineImagePath decodes the image: a UTF-16 Windows path, or the filename alone
// in bytes for clients with no reachable path. socketowner published it only
// after checking the length; a reader of a shared ABI checks again.
func wineImagePath(value *wineFlowValue) (string, bool) {
	size := value.ImageBytes
	if value.Encoding == 1 {
		if size == 0 || size > wineImageBytes {
			return "", false
		}
		name := make([]byte, 0, size+1)
		for _, w := range value.Image[:(size+1)/2] {
			name = append(name, byte(w), byte(w>>8))
		}
		image := string(name[:size])
		if !utf8.ValidString(image) || strings.ContainsAny(image, "\x00/\\") {
			return "", false
		}
		return image, true
	}
	if value.Encoding != 0 || size < 2 || size > wineImageBytes || size%2 != 0 {
		return "", false
	}
	image := string(utf16.Decode(value.Image[:size/2]))
	if strings.ContainsRune(image, 0) || strings.ContainsRune(image, 0xfffd) {
		return "", false
	}
	image = strings.ReplaceAll(image, "/", `\`)
	image = strings.TrimPrefix(strings.TrimPrefix(image, `\??\`), `\\?\`)
	return image, true
}
