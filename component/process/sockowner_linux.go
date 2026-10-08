package process

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

const (
	soNetnsCookie = 71 // SO_NETNS_COOKIE, Linux 5.14
	// How often to check whether the loader has replaced the map, and how
	// soon to check again after a lookup misses, which may mean it has.
	sockOwnerRecheck     = 30 * time.Second
	sockOwnerMissRecheck = time.Second
)

type sockOwnerKey struct {
	Netns uint64
	Addr  [16]byte
	Port  uint16
	Proto uint8
	_     [5]byte
}

type sockOwnerValue struct {
	Tgid   uint32
	UID    uint32
	BootNs uint64 // CLOCK_BOOTTIME when the owner was recorded
}

// sockOwnerMap is the pinned map written by the socket-owner BPF programs
// (component/process/ebpf). When it can be opened, process lookup uses the
// owner recorded when a flow sent its first packet and falls back to the
// netlink and /proc lookup otherwise.
type sockOwnerMap struct {
	mu        sync.RWMutex
	path      string
	fd        int
	ino       uint64 // of the pinned file, to notice a new pin
	netns     uint64
	checkedAt time.Time
	warned    bool
}

var sockOwners = &sockOwnerMap{path: DefaultSockOwnerMap, fd: -1}

// SetSockOwnerMap sets the pinned socket-owner map to use; an empty path
// turns the lookup off.
func SetSockOwnerMap(path string) {
	m := sockOwners
	m.mu.Lock()
	defer m.mu.Unlock()
	if path == m.path {
		return
	}
	m.closeLocked()
	m.path = path
	m.checkedAt = time.Time{}
	m.warned = false
}

// SockOwnerMap returns the configured map path.
func SockOwnerMap() string {
	sockOwners.mu.RLock()
	defer sockOwners.mu.RUnlock()
	return sockOwners.path
}

func (m *sockOwnerMap) closeLocked() {
	if m.fd >= 0 {
		unix.Close(m.fd)
		m.fd = -1
	}
}

// lookup runs fn with the open map. It opens the map on first use and checks
// for a new pin periodically and after misses, since the loader may run after
// mihomo starts or be restarted.
func (m *sockOwnerMap) lookup(fn func(fd int, netns uint64) bool) bool {
	m.mu.RLock()
	age := time.Since(m.checkedAt)
	found := age < sockOwnerRecheck && m.fd >= 0 && fn(m.fd, m.netns)
	m.mu.RUnlock()
	if found || age < sockOwnerMissRecheck {
		return found
	}

	m.mu.Lock()
	if time.Since(m.checkedAt) >= sockOwnerMissRecheck {
		m.refreshLocked()
	}
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fd >= 0 && fn(m.fd, m.netns)
}

func (m *sockOwnerMap) refreshLocked() {
	m.checkedAt = time.Now()
	if m.path == "" {
		return
	}
	var st unix.Stat_t
	if err := unix.Stat(m.path, &st); err != nil {
		m.closeLocked()
		if !errors.Is(err, unix.ENOENT) {
			m.warnLocked(err)
		}
		return
	}
	if m.fd >= 0 && st.Ino == m.ino {
		return
	}
	m.closeLocked()
	fd, netns, err := openSockOwnerMap(m.path)
	if err != nil {
		m.warnLocked(err)
		return
	}
	m.fd, m.ino, m.netns = fd, st.Ino, netns
	m.warned = false
	log.Infoln("[Process] Using socket owners recorded in %s", m.path)
}

func (m *sockOwnerMap) warnLocked(err error) {
	if !m.warned {
		log.Warnln("[Process] Can't use socket owners recorded in %s: %v", m.path, err)
		m.warned = true
	}
}

func openSockOwnerMap(path string) (int, uint64, error) {
	netns, err := currentNetnsCookie()
	if err != nil {
		return -1, 0, err
	}
	pathname, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, 0, err
	}
	attr := struct {
		Pathname  uint64
		BpfFd     uint32
		FileFlags uint32
		PathFd    int32
		_         uint32
	}{
		Pathname:  uint64(uintptr(unsafe.Pointer(pathname))),
		FileFlags: unix.BPF_F_RDONLY,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, 0, fmt.Errorf("open %s: %w", path, errno)
	}
	unix.CloseOnExec(int(fd))
	if err := checkSockOwnerMap(int(fd)); err != nil {
		unix.Close(int(fd))
		return -1, 0, fmt.Errorf("%s: %w", path, err)
	}
	return int(fd), netns, nil
}

// checkSockOwnerMap makes sure the map has the type and layout lookups expect.
// The kernel copies a value of the map's own size into the lookup buffer, so
// a bigger value would overwrite memory beyond it.
func checkSockOwnerMap(fd int) error {
	var info struct {
		Type       uint32
		ID         uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
		MapFlags   uint32
		Name       [16]byte
	}
	attr := struct {
		BpfFd   uint32
		InfoLen uint32
		Info    uint64
	}{
		BpfFd:   uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return fmt.Errorf("map info: %w", errno)
	}
	if info.Type != unix.BPF_MAP_TYPE_LRU_HASH ||
		info.KeySize != uint32(unsafe.Sizeof(sockOwnerKey{})) ||
		info.ValueSize != uint32(unsafe.Sizeof(sockOwnerValue{})) {
		return fmt.Errorf("not a socket-owner map (type %d, key %d bytes, value %d bytes)",
			info.Type, info.KeySize, info.ValueSize)
	}
	return nil
}

func currentNetnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var cookie uint64
	size := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, soNetnsCookie,
		uintptr(unsafe.Pointer(&cookie)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, fmt.Errorf("SO_NETNS_COOKIE: %w", errno)
	}
	return cookie, nil
}

func lookupSockOwner(network string, ip netip.Addr, srcPort int) (sockOwnerValue, bool) {
	key := sockOwnerKey{Addr: ip.Unmap().As16(), Port: uint16(srcPort)}
	switch {
	case strings.HasPrefix(network, "tcp"):
		key.Proto = unix.IPPROTO_TCP
	case strings.HasPrefix(network, "udp"):
		key.Proto = unix.IPPROTO_UDP
	default:
		return sockOwnerValue{}, false
	}
	var value sockOwnerValue
	found := sockOwners.lookup(func(fd int, netns uint64) bool {
		key.Netns = netns
		attr := struct {
			MapFd uint32
			_     uint32
			Key   uint64
			Value uint64
			Flags uint64
		}{
			MapFd: uint32(fd),
			Key:   uint64(uintptr(unsafe.Pointer(&key))),
			Value: uint64(uintptr(unsafe.Pointer(&value))),
		}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		return errno == 0
	})
	if !found || value.Tgid == 0 {
		return sockOwnerValue{}, false
	}
	return value, true
}

var errSockOwnerGone = errors.New("socket owner exited")

// resolveSockOwnerPath returns the executable of the recorded owner.
//
// It doesn't check that the process ID still belongs to the owner. mihomo
// looks a flow up right after its first packet, so the owner would have to
// exit and the whole PID space wrap around in between. Checking would mean
// reading /proc/<pid>/stat of other users' processes, which hardened setups
// deny together with environ and mem. The table keeps the time each owner was
// recorded (BootNs) should a check become necessary.
func resolveSockOwnerPath(owner sockOwnerValue) (string, error) {
	exe, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(owner.Tgid), 10) + "/exe")
	if errors.Is(err, os.ErrNotExist) {
		return "", errSockOwnerGone
	}
	return exe, err
}
