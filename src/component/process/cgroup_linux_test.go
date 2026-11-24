package process

import (
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
	m := &sockOwnerMap{path: filepath.Join(t.TempDir(), "conn_owners"), fd: -1, tasksFd: -1, recentFd: -1, cgroupsFd: -1}
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
	// An ID above every known one is of a newer cgroup: walk right away.
	walked = c.walkedAt
	if _, ok := c.path(1 << 62); ok {
		t.Fatal("resolved a missing ID")
	}
	if c.walkedAt.Equal(walked) {
		t.Fatal("didn't walk again for a newer ID")
	}
}
