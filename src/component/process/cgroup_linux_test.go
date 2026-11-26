package process

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The owner-cgroup value of socketowner's conn_cgroups, as specified in
// socketowner/docs/map-interface.md.
func TestSockCgroupABILayout(t *testing.T) {
	for name, tc := range map[string]struct{ got, want uintptr }{
		"size":        {unsafe.Sizeof(sockCgroupValue{}), 24},
		"tgid":        {unsafe.Offsetof(sockCgroupValue{}.Tgid), 0},
		"time":        {unsafe.Offsetof(sockCgroupValue{}.BootNs), 8},
		"cgroup":      {unsafe.Offsetof(sockCgroupValue{}.CgroupID), 16},
		"path size":   {unsafe.Sizeof(cgroupPathValue{}), 1032},
		"path length": {unsafe.Offsetof(cgroupPathValue{}.Len), 0},
		"path bytes":  {unsafe.Offsetof(cgroupPathValue{}.Path), 8},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", name, tc.got, tc.want)
		}
	}
}

// The maps evict independently: a cgroup record of another owner, or of the
// same process ID recorded at another time, must read as unknown.
func TestSockCgroupBelongsTo(t *testing.T) {
	owner := sockOwnerValue{Tgid: 100, UID: 1000, BootNs: 5000}
	for name, tc := range map[string]struct {
		owner sockOwnerValue
		cg    sockCgroupValue
		want  bool
	}{
		"same owner":      {owner, sockCgroupValue{Tgid: 100, BootNs: 5000, CgroupID: 77}, true},
		"other tgid":      {owner, sockCgroupValue{Tgid: 101, BootNs: 5000, CgroupID: 77}, false},
		"other boot_ns":   {owner, sockCgroupValue{Tgid: 100, BootNs: 4999, CgroupID: 77}, false},
		"empty record":    {owner, sockCgroupValue{}, false},
		"no cgroup":       {owner, sockCgroupValue{Tgid: 100, BootNs: 5000}, false},
		"unknown owner":   {sockOwnerValue{}, sockCgroupValue{}, false},
		"unknown, zeroed": {sockOwnerValue{BootNs: 5000}, sockCgroupValue{BootNs: 5000, CgroupID: 77}, false},
	} {
		if got := tc.cg.belongsTo(tc.owner); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestCgroupPathDecode(t *testing.T) {
	set := func(s string, n int32) *cgroupPathValue {
		v := &cgroupPathValue{Len: n}
		copy(v.Path[:], s)
		return v
	}
	for name, tc := range map[string]struct {
		v    *cgroupPathValue
		want string
	}{
		"path":       {set("/user.slice/a.scope\x00junk", 20), "/user.slice/a.scope"},
		"root":       {set("/\x00", 2), "/"},
		"too long":   {set("/a", -36), ""},
		"empty":      {set("", 1), ""},
		"zero":       {set("", 0), ""},
		"overflow":   {set("/a", 1025), ""},
		"not rooted": {set("a\x00", 2), ""},
	} {
		got, ok := tc.v.path()
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("%s: %q, %v, want %q", name, got, ok, tc.want)
		}
	}
}

// A loader that predates conn_cgroups doesn't advertise it; the map is not
// opened and the reason is kept for the health snapshot.
func TestCgroupMapNeedsFeature(t *testing.T) {
	m := &sockOwnerMap{path: filepath.Join(t.TempDir(), "conn_owners"), fd: -1, tasksFd: -1, recentFd: -1, cgroupsFd: -1, flowsFd: -1}
	m.openCgroupMapLocked()
	if m.cgroupsFd >= 0 || !strings.Contains(m.cgroupErr, "update") {
		t.Fatalf("fd %d, error %q", m.cgroupsFd, m.cgroupErr)
	}
	m.features = featureConnCgroups
	m.openCgroupMapLocked()
	if m.cgroupsFd >= 0 || m.cgroupErr == "" {
		t.Fatalf("opened a missing map: fd %d, error %q", m.cgroupsFd, m.cgroupErr)
	}
}

// Without an open socket-owner map nothing is attributed, and nothing fails.
func TestFindCgroupWithoutMaps(t *testing.T) {
	defer SetSockOwnerMap(SockOwnerMap())
	SetSockOwnerMap(filepath.Join(t.TempDir(), "conn_owners"))
	if path, ok := FindCgroup("tcp", netip.MustParseAddr("127.0.0.1"), 1234); ok {
		t.Fatalf("attributed to %q", path)
	}
}

// walkCgroupDir names every directory by its inode. A temporary tree stands
// in for cgroupfs, which needs no special handling beyond its file system
// type.
func TestWalkCgroupDir(t *testing.T) {
	root := t.TempDir()
	dirs := []string{"a.slice", "a.slice/b.scope", "a.slice/b.scope/c", "d.service"}
	for _, d := range dirs {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a.slice", "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[uint64]string{}
	if err := walkCgroupDir(fd, "", 0, make([]byte, 256), byID); err != nil {
		t.Fatal(err)
	}
	if len(byID) != len(dirs) {
		t.Errorf("found %v", byID)
	}
	for _, d := range dirs {
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(root, d), &st); err != nil {
			t.Fatal(err)
		}
		if got := byID[st.Ino]; got != "/"+d {
			t.Errorf("inode %d: %q, want %q", st.Ino, got, "/"+d)
		}
	}
	if _, err := walkCgroups(root); err == nil {
		t.Error("walked a directory that isn't cgroupfs")
	}
}

// On a host with cgroup v2, this process's own cgroup resolves by its ID,
// and an ID that doesn't exist comes out unknown without another walk until
// the interval has passed.
func TestCgroupNamesHost(t *testing.T) {
	data, err := os.ReadFile("/proc/self/cgroup")
	own, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "0::")
	var fs unix.Statfs_t
	if err != nil || !ok || unix.Statfs(defaultCgroupRoot, &fs) != nil || fs.Type != cgroup2SuperMagic {
		t.Skip("no cgroup v2 at", defaultCgroupRoot)
	}
	var rootSt unix.Stat_t
	if err := unix.Stat(defaultCgroupRoot, &rootSt); err != nil {
		t.Skip("cgroup v2 root not visible:", err)
	}
	if rootSt.Ino != 1 {
		// A private cgroup namespace hides the host tree; the remaining
		// assertions need the host cgroup v2 root.
		if _, err := walkCgroups(defaultCgroupRoot); err == nil {
			t.Fatal("walked a private cgroup namespace")
		}
		t.Skip("private cgroup namespace")
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(defaultCgroupRoot, own), &st); err != nil {
		t.Skip("own cgroup not visible:", err)
	}
	c := &cgroupNames{root: defaultCgroupRoot}
	if got, ok := c.path(st.Ino); !ok || got != own {
		t.Fatalf("own cgroup %d: %q, %v, want %q", st.Ino, got, ok, own)
	}
	// A missing ID below the largest known one was removed: no new walk
	// until the interval has passed.
	walked := c.walkedAt
	if _, ok := c.path(st.Ino - 1); ok && c.byID[st.Ino-1] == "" {
		t.Fatal("resolved a missing ID")
	}
	if !c.walkedAt.Equal(walked) {
		t.Fatal("walked again within the interval")
	}
	c.walkedAt = time.Now().Add(-cgroupRewalkInterval)
	c.path(st.Ino - 1)
	if c.walkedAt.Equal(walked) {
		t.Fatal("didn't walk again after the interval")
	}
	// An ID above every known one is of a newer cgroup: walk right away,
	// then wait for the interval if it is still missing.
	walked = c.walkedAt
	if _, ok := c.path(1 << 62); ok {
		t.Fatal("resolved a missing ID")
	}
	if c.walkedAt.Equal(walked) {
		t.Fatal("didn't walk again for a newer ID")
	}
	walked = c.walkedAt
	if _, ok := c.path(1 << 62); ok {
		t.Fatal("resolved a missing ID")
	}
	if !c.walkedAt.Equal(walked) {
		t.Fatal("walked again for a missing high ID within the interval")
	}
}

// A failed walk is not retried for every lookup within the rewalk interval.
func TestCgroupNamesRewalkThrottle(t *testing.T) {
	walkErr := errors.New("cannot walk")
	walks := 0
	c := &cgroupNames{root: "/cgroup", walk: func(string) (map[uint64]string, error) {
		walks++
		return nil, walkErr
	}}
	for i := 0; i < 3; i++ {
		if _, ok := c.path(42); ok {
			t.Fatal("resolved an ID")
		}
	}
	if walks != 1 {
		t.Fatalf("walked %d times after an error, want 1", walks)
	}
	c.walkedAt = time.Now().Add(-cgroupRewalkInterval)
	c.path(42)
	if walks != 2 {
		t.Fatalf("walked %d times after the interval, want 2", walks)
	}
}

// A missing ID above every known one walks once, then waits for the interval
// like any other ID below the new maximum.
func TestCgroupNamesMissingHighID(t *testing.T) {
	walks := 0
	c := &cgroupNames{root: "/cgroup", walk: func(string) (map[uint64]string, error) {
		walks++
		return map[uint64]string{10: "/seen"}, nil
	}}
	if got, ok := c.path(10); !ok || got != "/seen" {
		t.Fatalf("known cgroup: %q, %v", got, ok)
	}
	if _, ok := c.path(20); ok {
		t.Fatal("resolved a missing ID")
	}
	if walks != 2 {
		t.Fatalf("walks %d, want 2", walks)
	}
	if c.maxID != 20 {
		t.Fatalf("maxID %d, want 20", c.maxID)
	}
	c.path(20)
	if walks != 2 {
		t.Fatalf("walked again for a missing high ID: %d", walks)
	}
}

// A cgroup that a later walk no longer finds stays named, and the retained
// paths stay bounded.
func TestCgroupNamesRetainsRemoved(t *testing.T) {
	walks := 0
	c := &cgroupNames{root: "/cgroup", walk: func(string) (map[uint64]string, error) {
		walks++
		if walks == 1 {
			return map[uint64]string{10: "/app/gone", 11: "/app/live"}, nil
		}
		return map[uint64]string{11: "/app/live"}, nil
	}}
	if got, ok := c.path(10); !ok || got != "/app/gone" {
		t.Fatalf("first walk: %q, %v", got, ok)
	}
	if _, ok := c.path(20); ok {
		t.Fatal("resolved a missing ID")
	}
	if got, ok := c.path(10); !ok || got != "/app/gone" {
		t.Fatalf("removed cgroup after rewalk: %q, %v", got, ok)
	}
	if known, err := c.health(); known != 1 || err != nil {
		t.Fatalf("health %d, %v; want 1, nil", known, err)
	}
}

func TestCgroupNamesRemovedBounded(t *testing.T) {
	first := make(map[uint64]string, cgroupRemovedLimit+100)
	for id := uint64(1); id <= cgroupRemovedLimit+100; id++ {
		first[id] = "/cgroup"
	}
	walks := 0
	c := &cgroupNames{root: "/cgroup", walk: func(string) (map[uint64]string, error) {
		walks++
		if walks == 1 {
			return first, nil
		}
		return map[uint64]string{}, nil
	}}
	if _, ok := c.path(cgroupRemovedLimit + 100); !ok {
		t.Fatal("didn't see the first walk")
	}
	if _, ok := c.path(cgroupRemovedLimit + 200); ok {
		t.Fatal("resolved a missing ID")
	}
	if got := len(c.removed); got != cgroupRemovedLimit {
		t.Fatalf("retained %d removed cgroups, want %d", got, cgroupRemovedLimit)
	}
	if got := len(c.removedOrder); got != cgroupRemovedLimit {
		t.Fatalf("removed order holds %d, want %d", got, cgroupRemovedLimit)
	}
}

// cgroupfs errors are reported only once a rule needs cgroups.
func TestCgroupNamesWarnsOnlyWhenWanted(t *testing.T) {
	previous := cgroupLookupWanted.Load()
	t.Cleanup(func() { cgroupLookupWanted.Store(previous) })
	cgroupLookupWanted.Store(false)
	walkErr := errors.New("permission denied")
	c := &cgroupNames{root: "/cgroup", walk: func(string) (map[uint64]string, error) {
		return nil, walkErr
	}}
	c.path(1)
	if c.warned != "" {
		t.Fatalf("warned %q without a rule", c.warned)
	}
	cgroupLookupWanted.Store(true)
	c.path(1)
	if c.warned != walkErr.Error() {
		t.Fatalf("warned %q, want %q", c.warned, walkErr)
	}
}

// A loader that advertises -exec-paths keeps cgroup names in BPF, so a failed
// map still reads as BPF and no lookup falls back to cgroupfs.
func TestCgroupPathsBPFWithoutMaps(t *testing.T) {
	m := &sockOwnerMap{fd: 3, cgroupsFd: -1, pathsFd: -1, features: featureCgroupPaths, cgroupErr: "cgroup_paths: missing"}
	m.mu.RLock()
	path, ok, usesMap := m.recordedCgroupPathLocked(1)
	m.mu.RUnlock()
	if ok || path != "" || !usesMap {
		t.Fatalf("recorded path %q, %v, %v; want empty, false, true", path, ok, usesMap)
	}
	previous := cgroupPaths
	cgroupPaths = &cgroupNames{root: defaultCgroupRoot, walk: func(string) (map[uint64]string, error) {
		t.Error("walked cgroupfs with -exec-paths advertised")
		return nil, nil
	}}
	t.Cleanup(func() { cgroupPaths = previous })
	health := m.cgroupHealth()
	if health.Source != "bpf" || health.Available || health.MapError != m.cgroupErr {
		t.Fatalf("health %+v", health)
	}
	if health.Root != "" || health.KnownCgroups != 0 {
		t.Fatalf("health listed cgroupfs: %+v", health)
	}
}

// Without conn_cgroups, a flow record's cgroup ID is not used even when
// conn_flows is open, and cgroup unavailability is recorded.
func TestLookupSockCgroupNeedsCgroupMap(t *testing.T) {
	previous := sockOwners
	previousWanted := cgroupLookupWanted.Load()
	cgroupLookupWanted.Store(true)
	t.Cleanup(func() {
		sockOwners = previous
		cgroupLookupWanted.Store(previousWanted)
	})
	sockOwners = &sockOwnerMap{
		fd:        3,
		cgroupsFd: -1,
		flowsFd:   3,
		features:  featureCgroupPaths,
		cgroupErr: "cgroup_paths: missing",
		pinned:    pinnedMapSet{checkedAt: time.Now()},
	}
	if id, _, ok, _ := lookupSockCgroup("tcp", netip.MustParseAddr("127.0.0.1"), 1234, nil); ok {
		t.Fatalf("attributed cgroup %d without the cgroups map", id)
	}
	if !sockOwners.cgroupWarned {
		t.Fatal("did not note cgroup unavailability when cgroupsFd < 0")
	}
}
