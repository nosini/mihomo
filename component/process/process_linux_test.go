//go:build linux && !android

package process

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

type procEntryWithInfoError struct {
	os.DirEntry
	err error
}

func (e procEntryWithInfoError) Info() (os.FileInfo, error) {
	return nil, e.err
}

func TestResolveProcessNameByProcEntries(t *testing.T) {
	// Keep a real socket open so the later entry has a matching /proc/<pid>/fd.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Ino > uint64(^uint32(0)) {
		t.Fatalf("socket inode %d does not fit in uint32", stat.Ino)
	}
	inode, uid := uint32(stat.Ino), uint32(os.Getuid())
	want, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var matching os.DirEntry
	for _, entry := range entries {
		if entry.Name() == strconv.Itoa(os.Getpid()) {
			matching = entry
			break
		}
	}
	if matching == nil {
		t.Fatal("current process missing from /proc")
	}

	// Enumerate a numeric directory, then remove it before Info() is called.
	root := t.TempDir()
	vanishedPath := filepath.Join(root, "1")
	if err := os.Mkdir(vanishedPath, 0700); err != nil {
		t.Fatal(err)
	}
	vanished, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vanishedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := vanished[0].Info(); !os.IsNotExist(err) {
		t.Fatalf("vanished entry Info() error = %v, want not-exist", err)
	}

	t.Run("vanished entry before matching process", func(t *testing.T) {
		got, err := resolveProcessNameByProcEntries([]os.DirEntry{vanished[0], matching}, inode, uid)
		if err != nil || got != want {
			t.Fatalf("process = %q, error = %v; want %q, nil", got, err, want)
		}
	})
	t.Run("other stat error", func(t *testing.T) {
		statErr := &os.PathError{Op: "lstat", Path: vanishedPath, Err: unix.EACCES}
		denied := procEntryWithInfoError{DirEntry: vanished[0], err: statErr}
		got, err := resolveProcessNameByProcEntries([]os.DirEntry{denied, matching}, inode, uid)
		if got != "" || !errors.Is(err, statErr) {
			t.Fatalf("process = %q, error = %v; want empty process, %v", got, err, statErr)
		}
	})
	t.Run("no matching process", func(t *testing.T) {
		got, err := resolveProcessNameByProcEntries(vanished, inode, uid)
		wantErr := fmt.Sprintf("process of uid(%d),inode(%d) not found", uid, inode)
		if got != "" || err == nil || err.Error() != wantErr {
			t.Fatalf("process = %q, error = %v; want empty process, %s", got, err, wantErr)
		}
	})
	t.Run("full proc search", func(t *testing.T) {
		got, err := resolveProcessNameByProcSearch(inode, uid)
		if err != nil || got != want {
			t.Fatalf("process = %q, error = %v; want %q, nil", got, err, want)
		}
	})
}
