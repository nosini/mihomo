package process

import (
	"bytes"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

// The owner-cgroup map socketowner pins next to the socket-owner map when
// abi_version advertises it (docs/socketowner.md).
const (
	connCgroupsMap        = "conn_cgroups"
	cgroupPathsMap        = "cgroup_paths"
	cgroupPathSize        = 1024
	featureConnCgroups    = 1 << 0
	featureCgroupPaths    = 1 << 1
	defaultCgroupRoot     = "/sys/fs/cgroup"
	cgroup2SuperMagic     = 0x63677270
	cgroupRewalkInterval  = time.Second
	cgroupWalkDepthLimit  = 64
	cgroupWalkBufferBytes = 32 << 10
)

// sockCgroupValue is the cgroup published for a connection, with the owner it
// belongs to.
type sockCgroupValue struct {
	Tgid     uint32
	_        uint32
	BootNs   uint64
	CgroupID uint64
}

// belongsTo reports whether the cgroup record is that of the owner record
// read from the socket-owner map. The two maps are evicted and written
// independently, so a record of another owner means the cgroup is unknown.
func (v *sockCgroupValue) belongsTo(owner sockOwnerValue) bool {
	return owner.Tgid != 0 && v.Tgid == owner.Tgid && v.BootNs == owner.BootNs && v.CgroupID != 0
}

// cgroupPathValue is a path recorded in cgroup_paths, relative to the cgroup
// v2 root.
type cgroupPathValue struct {
	Len  int32 // bytes in Path including the NUL, or a negative errno
	_    uint32
	Path [cgroupPathSize]byte
}

func (v *cgroupPathValue) path() (string, bool) {
	if v.Len < 2 || int(v.Len) > len(v.Path) || v.Path[0] != '/' {
		return "", false
	}
	return string(v.Path[:v.Len-1]), true
}

// openCgroupMapLocked opens conn_cgroups, and cgroup_paths where the loader
// records it (with -exec-paths), beside the open socket-owner map.
func (m *sockOwnerMap) openCgroupMapLocked() {
	if m.features&featureConnCgroups == 0 {
		m.cgroupErr = "the socketowner loader doesn't publish owner cgroups (update it)"
		return
	}
	dir := filepath.Dir(m.path)
	fd, err := openBPFMap(filepath.Join(dir, connCgroupsMap), unix.BPF_MAP_TYPE_LRU_HASH,
		uint32(unsafe.Sizeof(sockOwnerKey{})), sockCgroupValue{})
	if err != nil {
		m.cgroupErr = err.Error()
		return
	}
	if m.features&featureCgroupPaths != 0 {
		pathsFd, err := openBPFMap(filepath.Join(dir, cgroupPathsMap), unix.BPF_MAP_TYPE_LRU_HASH, 8, cgroupPathValue{})
		if err != nil {
			unix.Close(fd)
			m.cgroupErr = err.Error()
			return
		}
		m.pathsFd = pathsFd
	}
	m.cgroupsFd = fd
	m.cgroupErr = ""
}

// recordedCgroupPath returns the path the loader recorded for a cgroup ID.
// usesMap is false when the loader records no paths, so that the caller
// names the cgroup through cgroupfs instead.
func (m *sockOwnerMap) recordedCgroupPath(id uint64) (path string, ok, usesMap bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.pathsFd < 0 {
		return "", false, false
	}
	var v cgroupPathValue
	if !lookupBPFMap(m.pathsFd, &id, &v) {
		return "", false, true
	}
	path, ok = v.path()
	return path, ok, true
}

// noteCgroupUnavailable logs once per pin that cgroup attribution, which a
// rule needs, is unavailable.
func (m *sockOwnerMap) noteCgroupUnavailable() {
	if !cgroupLookupWanted.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cgroupWarned || m.fd < 0 || m.cgroupsFd >= 0 {
		return
	}
	m.cgroupWarned = true
	log.Warnln("[Process] Can't attribute connections to cgroups, so FLATPAK-APP rules match nothing: %s", m.cgroupErr)
}

// lookupSockCgroup returns the cgroup ID recorded for a connection's owner.
func lookupSockCgroup(network string, ip netip.Addr, srcPort int) (uint64, bool) {
	key, ok := newSockOwnerKey(network, ip, srcPort)
	if !ok {
		return 0, false
	}
	m := sockOwners
	var owner sockOwnerValue
	var cg sockCgroupValue
	unavailable := false
	// fn runs with m.mu held for reading.
	found := m.lookup(func(fd int, netns uint64) bool {
		key.Netns = netns
		if !lookupBPFMap(fd, &key, &owner) || owner.Tgid == 0 {
			return false
		}
		if m.cgroupsFd < 0 {
			unavailable = true
			return false
		}
		return lookupBPFMap(m.cgroupsFd, &key, &cg) && cg.belongsTo(owner)
	})
	if unavailable {
		m.noteCgroupUnavailable()
	}
	if !found {
		return 0, false
	}
	return cg.CgroupID, true
}

func findCgroup(network string, ip netip.Addr, srcPort int) (string, bool) {
	id, ok := lookupSockCgroup(network, ip, srcPort)
	if !ok {
		lookupCounters.cgroupUnknown.Add(1)
		return "", false
	}
	// A loader that records paths knows every cgroup its hooks saw, so a
	// missing entry stays unknown rather than sending mihomo to cgroupfs.
	path, ok, usesMap := sockOwners.recordedCgroupPath(id)
	if !usesMap {
		path, ok = cgroupPaths.path(id)
	}
	if !ok {
		lookupCounters.cgroupUnknown.Add(1)
		return "", false
	}
	lookupCounters.cgroupKnown.Add(1)
	return path, true
}

// cgroupNames maps cgroup v2 IDs to paths by walking cgroupfs. An ID is the
// inode number of the cgroup's directory, and IDs aren't reused, so a path
// found for an ID stays right for as long as it is kept. IDs also only grow,
// so an ID above every one the last walk found belongs to a cgroup created
// since, and is looked for in a new walk straight away. Other missing IDs are
// mostly of cgroups removed before that walk; they are looked for again at
// most once per cgroupRewalkInterval, which also covers a cgroup created in a
// directory while the walk was past it. A cgroup removed before a walk finds
// it can't be named and comes out unknown.
type cgroupNames struct {
	mu       sync.Mutex
	root     string
	byID     map[uint64]string
	maxID    uint64
	walkedAt time.Time
	err      error
	warned   string
}

var cgroupPaths = &cgroupNames{root: defaultCgroupRoot}

func (c *cgroupNames) path(id uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.byID[id]; ok {
		return p, true
	}
	if id <= c.maxID && time.Since(c.walkedAt) < cgroupRewalkInterval {
		return "", false
	}
	c.walkLocked()
	p, ok := c.byID[id]
	return p, ok
}

func (c *cgroupNames) walkLocked() {
	c.walkedAt = time.Now()
	byID, err := walkCgroups(c.root)
	c.err = err
	if err != nil {
		if text := err.Error(); text != c.warned {
			c.warned = text
			log.Warnln("[Process] Can't read cgroup names from %s: %v", c.root, err)
		}
		return
	}
	c.warned = ""
	c.byID = byID
	c.maxID = 0
	for id := range byID {
		if id > c.maxID {
			c.maxID = id
		}
	}
}

// health reports whether cgroupfs could be read, walking it if it never was,
// and how many cgroups are known.
func (c *cgroupNames) health() (known int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.walkedAt.IsZero() {
		c.walkLocked()
	}
	return len(c.byID), c.err
}

// walkCgroups lists every cgroup below root by directory inode. The root
// itself is "/". Directory entries carry the inode, so no cgroup needs to be
// opened except to list its children.
func walkCgroups(root string) (map[uint64]string, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		return nil, err
	}
	if fs.Type != cgroup2SuperMagic {
		return nil, fmt.Errorf("%s is not a cgroup v2 file system", root)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	byID := map[uint64]string{st.Ino: "/"}
	buf := make([]byte, cgroupWalkBufferBytes)
	err = walkCgroupDir(fd, "", 0, buf, byID)
	return byID, err
}

// walkCgroupDir records the subdirectories of the directory open at fd, which
// it closes, and descends into them. A cgroup removed during the walk, or one
// that can't be listed, is left out with its descendants.
func walkCgroupDir(fd int, path string, depth int, buf []byte, byID map[uint64]string) error {
	defer unix.Close(fd)
	type child struct {
		name string
		ino  uint64
	}
	var children []child
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			if depth > 0 {
				return nil
			}
			return err
		}
		if n <= 0 {
			break
		}
		for off := 0; off < n; {
			// struct linux_dirent64: ino, off, reclen, type, name.
			ino := *(*uint64)(unsafe.Pointer(&buf[off]))
			reclen := int(*(*uint16)(unsafe.Pointer(&buf[off+16])))
			typ := buf[off+18]
			name := buf[off+19 : off+reclen]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			off += reclen
			if typ != unix.DT_DIR || string(name) == "." || string(name) == ".." {
				continue
			}
			children = append(children, child{string(name), ino})
		}
	}
	for _, c := range children {
		p := path + "/" + c.name
		byID[c.ino] = p
		if depth+1 >= cgroupWalkDepthLimit {
			continue
		}
		sub, err := unix.Openat(fd, c.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		if err := walkCgroupDir(sub, p, depth+1, buf, byID); err != nil {
			return err
		}
	}
	return nil
}

// cgroupHealth reports cgroup attribution for a health snapshot. It runs after
// mapsHealth, which has refreshed the publication point.
func (m *sockOwnerMap) cgroupHealth() CgroupHealth {
	m.mu.RLock()
	health := CgroupHealth{MapOpen: m.cgroupsFd >= 0, PathsMapOpen: m.pathsFd >= 0}
	if m.fd >= 0 && m.cgroupsFd < 0 {
		health.MapError = m.cgroupErr
	}
	m.mu.RUnlock()
	if health.PathsMapOpen {
		health.Source = "bpf"
		health.Available = health.MapOpen
		return health
	}
	health.Source = "cgroupfs"
	health.Root = cgroupPaths.root
	known, err := cgroupPaths.health()
	health.KnownCgroups = known
	if err != nil {
		health.RootError = err.Error()
	}
	health.Available = health.MapOpen && err == nil
	return health
}
