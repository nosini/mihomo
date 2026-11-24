package process

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/metacubex/mihomo/log"

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
// healthState and healthChecked remember the last publication sample, so
// changes are logged once and lookups sample at most every wineHeartbeatLimit.
type wineFlows struct {
	mu            sync.RWMutex
	flowsFd       int
	heartbeatFd   int
	netns         uint64
	pinned        pinnedMapSet
	healthState   atomic.Int32
	healthChecked atomic.Int64
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

func (w *wineFlows) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked()
	w.pinned.reset("")
	// A changed map path makes the next sample a first observation, so it
	// logs nothing.
	w.healthState.Store(int32(wineStateUnknown))
}

func (w *wineFlows) openLocked(dir string) error {
	if err := checkABI(filepath.Join(dir, wineABIMap), wineABIVersion); err != nil {
		return fmt.Errorf("Wine ABI: %w", err)
	}
	netns, err := currentNetnsCookie()
	if err != nil {
		return err
	}
	heartbeat, err := openBPFMap(filepath.Join(dir, wineHeartbeatMap), unix.BPF_MAP_TYPE_ARRAY, 4, uint64(0))
	if err != nil {
		return err
	}
	flows, err := openBPFMap(filepath.Join(dir, wineFlowsMap), unix.BPF_MAP_TYPE_LRU_HASH,
		uint32(unsafe.Sizeof(sockOwnerKey{})), wineFlowValue{})
	if err != nil {
		unix.Close(heartbeat)
		return err
	}
	w.flowsFd, w.heartbeatFd, w.netns = flows, heartbeat, netns
	return nil
}

func (w *wineFlows) refreshLocked(dir string) bool {
	changed, err := w.pinned.refresh(filepath.Join(dir, wineFlowsMap), w.closeLocked, func() error {
		return w.openLocked(dir)
	})
	if err != nil && w.pinned.warnOnce(err) {
		log.Warnln("[Process] Can't use Wine maps in %s: %v", dir, err)
	}
	return changed
}

// heartbeatAgeLocked returns the age of the Wine publisher's heartbeat. ok is
// false when it can't be read, which the reader treats as not live.
func (w *wineFlows) heartbeatAgeLocked() (time.Duration, bool) {
	var slot uint32
	var beat uint64
	var now unix.Timespec
	if !lookupBPFMap(w.heartbeatFd, &slot, &beat) || unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return 0, false
	}
	return time.Duration(now.Nano() - int64(beat)), true
}

// lookup returns the record of a flow, given its key without the namespace.
// live is false if its publisher stopped beating, which leaves records
// unmaintained: a port may have changed hands.
func (w *wineFlows) lookup(key *sockOwnerKey, dir string) (value wineFlowValue, live, found bool) {
	w.mu.RLock()
	stale := w.pinned.stale()
	w.mu.RUnlock()
	if stale {
		w.mu.Lock()
		if w.pinned.stale() {
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
	// The publisher writes host CLOCK_BOOTTIME; a beat from the future means
	// another clock, so it proves nothing.
	if age, ok := w.heartbeatAgeLocked(); ok {
		live = age >= 0 && age < wineHeartbeatLimit
	}
	return value, live, true
}

// wineFlowsDir returns the directory of the Wine maps beside the configured
// socket-owner map. An empty owner path disables them; a relative owner path
// keeps the Wine maps relative too, so a map in the working directory works.
func wineFlowsDir(ownerPath string) (string, bool) {
	if ownerPath == "" {
		return "", false
	}
	return filepath.Dir(ownerPath), true
}

// findWineProcess names the Windows program behind a flow, which is reported
// beside the process owning the socket, such as a sandbox's relay. ok is false
// when no Wine record covers it. An unusable record gives WineUnknown, so that
// a rule for a Windows program is never passed for lack of its identity.
func findWineProcess(network string, ip netip.Addr, srcPort int) (name, path string, ok bool) {
	key, ok := newSockOwnerKey(network, ip, srcPort)
	if !ok {
		return "", "", false
	}
	sockOwners.mu.RLock()
	defer sockOwners.mu.RUnlock()
	dir, enabled := wineFlowsDir(sockOwners.path)
	if !enabled {
		return "", "", false
	}
	// Sample the publication state while looking flows up, so a stopped
	// publisher is noticed even without the /process-lookup route.
	noteWineHealth(dir)
	value, live, found := wineFlowMaps.lookup(&key, dir)
	if !found {
		return "", "", false
	}
	if !live {
		lookupCounters.wineStaleRefused.Add(1)
		return WineUnknown, WineUnknown, true
	}
	if value.Status != wineStatusKnown || uint32(key.Proto) != value.Protocol {
		lookupCounters.wineUnknown.Add(1)
		return WineUnknown, WineUnknown, true
	}
	if name, path, ok = wineImage(&value); !ok {
		lookupCounters.wineUnknown.Add(1)
		return WineUnknown, WineUnknown, true
	}
	lookupCounters.wineKnown.Add(1)
	return name, path, true
}

// wineImage decodes the image as socketowner does: an absolute UTF-16 Windows
// drive or UNC path, or for 32-bit clients only the filename in bytes, with no
// reachable Windows path. BPF copies it from the client's memory unchecked, so
// it is validated here as socketowner's observer validates it, and a malformed
// image is never a usable name.
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
		return name, "", true
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
	// Only an NT or Win32 device prefix makes a following UNC\ a share path; a
	// bare UNC\ is relative.
	stripped := false
	if t := strings.TrimPrefix(path, `\??\`); t != path {
		path, stripped = t, true
	} else if t := strings.TrimPrefix(path, `\\?\`); t != path {
		path, stripped = t, true
	}
	if stripped && strings.HasPrefix(path, `UNC\`) {
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
