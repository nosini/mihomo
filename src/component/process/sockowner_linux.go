package process

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
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
	// socketowner's map interface is versioned independently of mihomo.
	sockOwnerABIVersion uint32 = 1
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

func newSockOwnerKey(network string, ip netip.Addr, srcPort int) (sockOwnerKey, bool) {
	key := sockOwnerKey{Addr: ip.Unmap().As16(), Port: uint16(srcPort)}
	switch {
	case strings.HasPrefix(network, "tcp"):
		key.Proto = unix.IPPROTO_TCP
	case strings.HasPrefix(network, "udp"):
		key.Proto = unix.IPPROTO_UDP
	default:
		return sockOwnerKey{}, false
	}
	return key, true
}

// pinnedMapSet tracks one pinned-map publication point: its path, the inode
// of the pin that is open, and when it was last checked. Both the socket-owner
// maps and the Wine maps use it to notice a loader restart and to warn about
// a publication point they can't use.
type pinnedMapSet struct {
	path      string
	ino       uint64
	checkedAt time.Time
	warned    string
}

// reset forgets the open pin and its warnings.
func (p *pinnedMapSet) reset(path string) {
	p.path = path
	p.ino = 0
	p.checkedAt = time.Time{}
	p.warned = ""
}

// stale reports whether the pin should be checked again before trusting a
// miss.
func (p *pinnedMapSet) stale() bool {
	return time.Since(p.checkedAt) >= sockOwnerMissRecheck
}

// warnOnce reports whether err should be logged. A repeated error stays
// quiet until a pin opens again or a different error occurs.
func (p *pinnedMapSet) warnOnce(err error) bool {
	text := err.Error()
	if p.warned == text {
		return false
	}
	p.warned = text
	return true
}

// refresh checks whether the publication point at path is still the open pin.
// If it was removed or replaced, close is called and open reopens it. changed
// reports whether the open maps changed, so that a caller which already
// missed can retry the lookup only then. A missing publication point is
// silent; other errors are returned for the caller to warn about.
func (p *pinnedMapSet) refresh(path string, close func(), open func() error) (changed bool, err error) {
	p.checkedAt = time.Now()
	p.path = path
	if path == "" {
		hadOpen := p.ino != 0
		close()
		p.ino = 0
		return hadOpen, nil
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		hadOpen := p.ino != 0
		close()
		p.ino = 0
		if errors.Is(err, unix.ENOENT) {
			return hadOpen, nil
		}
		return hadOpen, err
	}
	if p.ino != 0 && p.ino == st.Ino {
		return false, nil
	}
	close()
	if err := open(); err != nil {
		p.ino = 0
		return true, err
	}
	p.ino = st.Ino
	p.warned = ""
	return true, nil
}

// The executable maps defined by socketowner ABI v1 (docs/socketowner.md). The
// loader pins these next to the socket-owner map with -exec-paths:
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
// from the separate socketowner repository. When opened, process lookup uses the
// owner recorded when a flow sent its first packet and falls back to the
// netlink and /proc lookup otherwise, unless only is set. The owner's
// executable comes from the exec-path maps where the loader pinned them, and
// from /proc otherwise.
type sockOwnerMap struct {
	mu       sync.RWMutex
	path     string
	only     bool
	fd       int
	tasksFd  int
	recentFd int
	// cgroupsFd is conn_cgroups and pathsFd cgroup_paths, each open while
	// the loader advertises it.
	cgroupsFd int
	pathsFd   int
	// flowsFd is conn_flows, open while the loader advertises it.
	flowsFd    int
	features   uint32
	netns      uint64
	pinned     pinnedMapSet
	execWarned bool
	// openErr and execErr are the last errors from opening the owner and
	// exec-path maps, for the health snapshot; empty while they are open.
	openErr   string
	execErr   string
	cgroupErr string
	// cgroupWarned is set once the missing cgroup map has been reported
	// for the open pin.
	cgroupWarned bool
}

var sockOwners = &sockOwnerMap{path: DefaultSockOwnerMap, fd: -1, tasksFd: -1, recentFd: -1, cgroupsFd: -1, pathsFd: -1, flowsFd: -1}

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
	m.pinned.reset(path)
	m.openErr, m.execErr, m.cgroupErr = "", "", ""
	m.execWarned, m.cgroupWarned = false, false
	wineFlowMaps.reset()
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
	m.features = 0
	for _, fd := range []*int{&m.fd, &m.tasksFd, &m.recentFd, &m.cgroupsFd, &m.pathsFd, &m.flowsFd} {
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
	age := time.Since(m.pinned.checkedAt)
	looked := age < sockOwnerRecheck && m.fd >= 0
	found := looked && fn(m.fd, m.netns)
	m.mu.RUnlock()
	if found || age < sockOwnerMissRecheck {
		return found
	}

	m.mu.Lock()
	changed := false
	if m.pinned.stale() {
		changed = m.refreshLocked()
	}
	m.mu.Unlock()
	if looked && !changed {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fd >= 0 && fn(m.fd, m.netns)
}

func (m *sockOwnerMap) refreshLocked() bool {
	changed, err := m.pinned.refresh(m.path, m.closeLocked, func() error {
		fd, netns, features, err := openSockOwnerMap(m.path)
		if err != nil {
			return err
		}
		m.fd, m.netns, m.features = fd, netns, features
		return nil
	})
	if err != nil {
		m.openErr = err.Error()
		if m.pinned.warnOnce(err) {
			log.Warnln("[Process] Can't use socket owners recorded in %s: %v", m.path, err)
		}
	} else if m.fd >= 0 {
		m.openErr = ""
	}
	if m.fd < 0 {
		return changed
	}
	if changed {
		m.execWarned, m.cgroupWarned = false, false
	}
	if m.cgroupsFd < 0 {
		m.openCgroupMapLocked()
	}
	if m.flowsFd < 0 {
		m.openFlowMapLocked()
	}
	if !changed && m.tasksFd >= 0 {
		return changed
	}
	// The loader pins the exec-path maps before the socket-owner map, so
	// they are in place when a new socket-owner map is. They are retried
	// on their own until they open, so that a failure to open them doesn't
	// last as long as the socket-owner map does.
	dir := filepath.Dir(m.path)
	err = m.openExecMapsLocked(dir)
	switch {
	case err == nil:
		m.execErr = ""
		log.Infoln("[Process] Using socket owners and executables recorded in %s", dir)
		return changed
	case !errors.Is(err, unix.ENOENT) && !m.execWarned:
		log.Warnln("[Process] Can't use executables recorded in %s: %v", dir, err)
		m.execWarned = true
	}
	m.execErr = err.Error()
	if changed {
		log.Infoln("[Process] Using socket owners recorded in %s", m.path)
	}
	return changed
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

func openSockOwnerMap(path string) (fd int, netns uint64, features uint32, err error) {
	features, err = checkSockOwnerABI(filepath.Dir(path))
	if err != nil {
		return -1, 0, 0, err
	}
	netns, err = currentNetnsCookie()
	if err != nil {
		return -1, 0, 0, err
	}
	fd, err = openBPFMap(path, unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), sockOwnerValue{})
	if err != nil {
		return -1, 0, 0, err
	}
	return fd, netns, features, nil
}

// checkABI rejects an absent or incompatible marker before interpreting
// records in maps with the given ABI version. It also returns the optional
// features at key 1, which loaders that predate them don't have.
func checkABI(path string, want uint32) (features uint32, err error) {
	fd, err := openBPFMap(path, unix.BPF_MAP_TYPE_ARRAY, 4, uint32(0))
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var key, version uint32
	if !lookupBPFMap(fd, &key, &version) {
		return 0, fmt.Errorf("cannot read ABI version from %s", path)
	}
	if version != want {
		return 0, fmt.Errorf("unsupported ABI v%d in %s (need v%d)", version, path, want)
	}
	key = 1
	if !lookupBPFMap(fd, &key, &features) {
		features = 0
	}
	return features, nil
}

// checkSockOwnerABI rejects absent or incompatible markers before interpreting
// records. Map type and size checks below additionally protect lookup buffers.
func checkSockOwnerABI(dir string) (uint32, error) {
	features, err := checkABI(filepath.Join(dir, "abi_version"), sockOwnerABIVersion)
	if err != nil {
		return 0, fmt.Errorf("socketowner ABI (install a compatible socketowner loader): %w", err)
	}
	return features, nil
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
	runtime.KeepAlive(pathname)
	runtime.KeepAlive(&attr)
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
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&attr)
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
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	runtime.KeepAlive(&attr)
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
	runtime.KeepAlive(&cookie)
	runtime.KeepAlive(&size)
	if errno != 0 {
		return 0, fmt.Errorf("SO_NETNS_COOKIE: %w", errno)
	}
	return cookie, nil
}

// lookupSockOwner returns the recorded owner of a connection. peers are the
// destinations its outgoing packets may carry; the record of the exact flow
// is preferred, since sockets with different peers can share a source port.
func lookupSockOwner(network string, ip netip.Addr, srcPort int, peers []netip.AddrPort) (sockOwnerValue, bool) {
	key, ok := newSockOwnerKey(network, ip, srcPort)
	if !ok {
		return sockOwnerValue{}, false
	}
	var value sockOwnerValue
	// Only lookups that consulted the maps count: the health snapshot tells
	// the ones the closed maps never answered from the fallback counter.
	consulted := false
	found := sockOwners.lookup(func(fd int, netns uint64) bool {
		consulted = true
		key.Netns = netns
		if flow, ok := sockOwners.lookupFlowLocked(key, peers); ok {
			value = flow.owner()
			return true
		}
		return lookupBPFMap(fd, &key, &value)
	})
	if found && value.Tgid != 0 {
		lookupCounters.bpfHits.Add(1)
		return value, true
	}
	if consulted {
		lookupCounters.bpfMisses.Add(1)
	}
	return sockOwnerValue{}, false
}

var (
	errSockOwnerGone   = errors.New("socket owner exited")
	errNotInitialPidNS = errors.New("not in the initial PID namespace")
)

const procPidInitIno = 0xEFFFFFFC

var (
	pidNamespaceOnce    sync.Once
	pidNamespaceInitial bool
)

// inInitialPidNamespace reports whether the reader shares the host PID
// namespace, which the socketowner TGIDs name. Once is enough: a process
// can't move between namespaces.
func inInitialPidNamespace() bool {
	pidNamespaceOnce.Do(func() {
		// The link names the namespace inode, so no access to nsfs itself is
		// needed, which SELinux policies don't usually grant.
		link, err := os.Readlink("/proc/self/ns/pid")
		if err != nil {
			log.Warnln("[Process] Can't check the PID namespace: %v", err)
			return
		}
		pidNamespaceInitial = isInitialPidNamespace(link)
		if !pidNamespaceInitial {
			log.Warnln("[Process] Not in the initial PID namespace; can't resolve process paths from socket owners")
		}
	})
	return pidNamespaceInitial
}

// isInitialPidNamespace reports whether a /proc/<pid>/ns/pid link names the
// initial PID namespace.
func isInitialPidNamespace(link string) bool {
	return link == "pid:["+strconv.FormatUint(procPidInitIno, 10)+"]"
}

// sockOwnerPathFallback reports whether a failed sock-owner lookup may fall
// back to the usual netlink and /proc search. A reused process ID or a nested
// PID namespace must not: that search could name a different process.
func sockOwnerPathFallback(err error) bool {
	return !errors.Is(err, errSockOwnerGone) && !errors.Is(err, errNotInitialPidNS)
}

// resolveSockOwnerPath returns the executable of the recorded owner, from the
// exec-path maps if the loader pinned them and from /proc/<pid>/exe otherwise.
func resolveSockOwnerPath(owner sockOwnerValue) (string, error) {
	m := sockOwners
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !inInitialPidNamespace() {
		return "", errNotInitialPidNS
	}
	if m.tasksFd >= 0 {
		// With exec-path records, a miss is not a reason to read /proc:
		// that would name a reused process ID in the record's place.
		return m.execPathLocked(owner)
	}
	if m.only {
		return "", ErrNotFound
	}
	return readSockOwnerExe(owner)
}

// execPath decodes the recorded executable path.
func (v *execPathValue) execPath() (string, error) {
	switch {
	case v.Len < 0:
		return "", fmt.Errorf("not recorded: %w", unix.Errno(-v.Len))
	case v.Len <= 1:
		return "", errors.New("recorded path is empty")
	}
	if int(v.Len) > len(v.Path) {
		return "", fmt.Errorf("recorded path length %d exceeds %d", v.Len, len(v.Path))
	}
	return string(v.Path[:v.Len-1]), nil
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
	path, err := value.execPath()
	if err != nil {
		return "", fmt.Errorf("executable of process %d: %w", owner.Tgid, err)
	}
	return path, nil
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
