package process

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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

// The maps of executables (component/process/ebpf/bpf/execpath.c), which the
// loader pins next to the socket-owner map when it runs with -exec-paths:
// exec_tasks holds the record of every running process and is looked up by
// pidfd, exec_recent the last records by process ID, including processes
// that have exited.
const (
	execTasksMap  = "exec_tasks"
	execRecentMap = "exec_recent"
	execPathSize  = 1024
)

type execPathValue struct {
	StartNs uint64 // CLOCK_BOOTTIME when the process started
	ExitNs  uint64 // CLOCK_BOOTTIME when it was freed, or 0
	Len     int32  // bytes in Path including the NUL, or a negative errno
	_       uint32
	Path    [execPathSize]byte
}

// ownedBy reports whether the record is of the process that owner names: it
// must have started before the owner was recorded and, if it has exited,
// exited after that. Otherwise the process ID was reused in between.
func (v *execPathValue) ownedBy(owner sockOwnerValue) bool {
	return v.StartNs <= owner.BootNs && (v.ExitNs == 0 || v.ExitNs >= owner.BootNs)
}

// sockOwnerMap is the pinned map written by the socket-owner BPF programs
// (component/process/ebpf). When it can be opened, process lookup uses the
// owner recorded when a flow sent its first packet and falls back to the
// netlink and /proc lookup otherwise, unless only is set. The owner's
// executable comes from the exec-path maps where the loader pinned them, and
// from /proc otherwise.
type sockOwnerMap struct {
	mu         sync.RWMutex
	path       string
	only       bool
	fd         int
	tasksFd    int
	recentFd   int
	ino        uint64 // of the pinned file, to notice a new pin
	netns      uint64
	checkedAt  time.Time
	warned     bool
	execWarned bool
}

var sockOwners = &sockOwnerMap{path: DefaultSockOwnerMap, fd: -1, tasksFd: -1, recentFd: -1}

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
	m.execWarned = false
}

// SockOwnerMap returns the configured map path.
func SockOwnerMap() string {
	sockOwners.mu.RLock()
	defer sockOwners.mu.RUnlock()
	return sockOwners.path
}

// SetSockOwnerOnly sets whether process lookup uses the BPF maps alone. Then
// mihomo never searches /proc or reads other processes' exe links, so it
// needs no access to other processes, but only names processes that the maps
// know.
func SetSockOwnerOnly(only bool) {
	sockOwners.mu.Lock()
	defer sockOwners.mu.Unlock()
	sockOwners.only = only
}

// SockOwnerOnly reports whether process lookup uses the BPF maps alone.
func SockOwnerOnly() bool {
	sockOwners.mu.RLock()
	defer sockOwners.mu.RUnlock()
	return sockOwners.only
}

func (m *sockOwnerMap) closeLocked() {
	for _, fd := range []*int{&m.fd, &m.tasksFd, &m.recentFd} {
		if *fd >= 0 {
			unix.Close(*fd)
			*fd = -1
		}
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
	opened := false
	if m.fd < 0 || st.Ino != m.ino {
		m.closeLocked()
		fd, netns, err := openSockOwnerMap(m.path)
		if err != nil {
			m.warnLocked(err)
			return
		}
		m.fd, m.ino, m.netns = fd, st.Ino, netns
		m.warned = false
		m.execWarned = false
		opened = true
	} else if m.tasksFd >= 0 {
		return
	}
	// The loader pins the exec-path maps before the socket-owner map, so
	// they are in place when a new socket-owner map is. They are retried
	// on their own until they open, so that a failure to open them doesn't
	// last as long as the socket-owner map does.
	dir := filepath.Dir(m.path)
	err := m.openExecMapsLocked(dir)
	switch {
	case err == nil:
		log.Infoln("[Process] Using socket owners and executables recorded in %s", dir)
		return
	case !errors.Is(err, unix.ENOENT) && !m.execWarned:
		log.Warnln("[Process] Can't use executables recorded in %s: %v", dir, err)
		m.execWarned = true
	}
	if opened {
		log.Infoln("[Process] Using socket owners recorded in %s", m.path)
	}
}

func (m *sockOwnerMap) openExecMapsLocked(dir string) error {
	tasksFd, err := openBPFMap(filepath.Join(dir, execTasksMap), unix.BPF_MAP_TYPE_TASK_STORAGE, 4, execPathValue{})
	if err != nil {
		return err
	}
	recentFd, err := openBPFMap(filepath.Join(dir, execRecentMap), unix.BPF_MAP_TYPE_LRU_HASH, 4, execPathValue{})
	if err != nil {
		unix.Close(tasksFd)
		return err
	}
	m.tasksFd, m.recentFd = tasksFd, recentFd
	return nil
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
	fd, err := openBPFMap(path, unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), sockOwnerValue{})
	if err != nil {
		return -1, 0, err
	}
	return fd, netns, nil
}

// openBPFMap opens the map pinned at path read-only and checks that it has
// the expected type, key size and value type.
func openBPFMap[V any](path string, mapType, keySize uint32, value V) (int, error) {
	pathname, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, err
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
		return -1, fmt.Errorf("open %s: %w", path, errno)
	}
	unix.CloseOnExec(int(fd))
	if err := checkBPFMap(int(fd), mapType, keySize, uint32(unsafe.Sizeof(value))); err != nil {
		unix.Close(int(fd))
		return -1, fmt.Errorf("%s: %w", path, err)
	}
	return int(fd), nil
}

// checkBPFMap makes sure the map has the type and layout lookups expect. The
// kernel copies a value of the map's own size into the lookup buffer, so a
// bigger value would overwrite memory beyond it.
func checkBPFMap(fd int, mapType, keySize, valueSize uint32) error {
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
	if info.Type != mapType || info.KeySize != keySize || info.ValueSize != valueSize {
		return fmt.Errorf("unexpected map layout (type %d, key %d bytes, value %d bytes)",
			info.Type, info.KeySize, info.ValueSize)
	}
	return nil
}

func lookupBPFMap[K, V any](fd int, key *K, value *V) bool {
	attr := struct {
		MapFd uint32
		_     uint32
		Key   uint64
		Value uint64
		Flags uint64
	}{
		MapFd: uint32(fd),
		Key:   uint64(uintptr(unsafe.Pointer(key))),
		Value: uint64(uintptr(unsafe.Pointer(value))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	return errno == 0
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
		return lookupBPFMap(fd, &key, &value)
	})
	if !found || value.Tgid == 0 {
		return sockOwnerValue{}, false
	}
	return value, true
}

var errSockOwnerGone = errors.New("socket owner exited")

// resolveSockOwnerPath returns the executable of the recorded owner, from the
// exec-path maps if the loader pinned them and from /proc/<pid>/exe otherwise.
func resolveSockOwnerPath(owner sockOwnerValue) (string, error) {
	m := sockOwners
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tasksFd >= 0 {
		path, err := m.execPathLocked(owner)
		if err == nil || m.only {
			return path, err
		}
	} else if m.only {
		return "", ErrNotFound
	}
	return readSockOwnerExe(owner)
}

// execPathLocked looks the owner up in the running processes and then among
// the recent ones, which include those that have exited.
func (m *sockOwnerMap) execPathLocked(owner sockOwnerValue) (string, error) {
	var value execPathValue
	found := false
	// A pidfd names one process, so the record can't change to another
	// process's between opening it and the lookup. Opening it needs no
	// access to the process.
	if pidfd, err := unix.PidfdOpen(int(owner.Tgid), 0); err == nil {
		key := int32(pidfd)
		found = lookupBPFMap(m.tasksFd, &key, &value) && value.ownedBy(owner)
		unix.Close(pidfd)
	}
	if !found {
		key := owner.Tgid
		found = lookupBPFMap(m.recentFd, &key, &value) && value.ownedBy(owner)
	}
	if !found {
		return "", errSockOwnerGone
	}
	if value.Len <= 0 || int(value.Len) > len(value.Path) {
		return "", fmt.Errorf("executable of process %d not recorded: %w", owner.Tgid, unix.Errno(-value.Len))
	}
	return string(value.Path[:value.Len-1]), nil
}

// readSockOwnerExe reads the executable of the recorded owner from /proc.
//
// It doesn't check that the process ID still belongs to the owner. mihomo
// looks a flow up right after its first packet, so the owner would have to
// exit and the whole PID space wrap around in between. Checking would mean
// reading /proc/<pid>/stat of other users' processes, which hardened setups
// deny together with environ and mem. The exec-path maps record start times
// and don't have this problem.
func readSockOwnerExe(owner sockOwnerValue) (string, error) {
	exe, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(owner.Tgid), 10) + "/exe")
	if errors.Is(err, os.ErrNotExist) {
		return "", errSockOwnerGone
	}
	return exe, err
}
