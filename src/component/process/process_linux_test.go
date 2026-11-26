//go:build linux && !android

package process

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"unsafe"

	"github.com/mdlayher/netlink"
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

func diagMessage(family byte, src, dst netip.Addr, srcPort, dstPort uint16, uid, inode uint32) netlink.Message {
	var resp inetDiagResponse
	resp.Family = family
	binary.BigEndian.PutUint16(resp.SrcPort[:], srcPort)
	binary.BigEndian.PutUint16(resp.DstPort[:], dstPort)
	if family == unix.AF_INET {
		s4 := src.As4()
		d4 := dst.As4()
		copy(resp.Src[:4], s4[:])
		copy(resp.Dst[:4], d4[:])
	} else {
		s16 := src.As16()
		d16 := dst.As16()
		copy(resp.Src[:], s16[:])
		copy(resp.Dst[:], d16[:])
	}
	resp.UID = uid
	resp.INode = inode
	raw := (*(*[inetDiagResponseSize]byte)(unsafe.Pointer(&resp)))[:]
	data := append([]byte(nil), raw...)
	return netlink.Message{Data: data}
}

func TestMatchInetDiagResponses(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.1")
	otherIP := netip.MustParseAddr("198.18.0.2")
	peerA := netip.MustParseAddrPort("1.1.1.1:443")
	peerB := netip.MustParseAddrPort("2.2.2.2:443")

	t.Run("unmatched dump returns ErrNotFound", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, otherIP, peerA.Addr(), 5000, 443, 1001, 111),
			diagMessage(unix.AF_INET, src, peerA.Addr(), 5001, 443, 1002, 222),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerA}, true)
		if !errors.Is(err, ErrNotFound) || uid != 0 || inode != 0 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 0, 0, ErrNotFound", uid, inode, err)
		}
	})

	t.Run("prefers exact peer on shared source port", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, src, peerA.Addr(), 5000, 443, 1001, 111),
			diagMessage(unix.AF_INET6, netip.AddrFrom16(src.As16()), netip.AddrFrom16(peerB.Addr().As16()), 5000, 443, 1002, 222),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerB}, true)
		if err != nil || uid != 1002 || inode != 222 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1002, 222, nil", uid, inode, err)
		}
	})

	t.Run("prefers unconnected UDP socket over unrelated peer", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, src, peerA.Addr(), 5000, 443, 1001, 111),
			diagMessage(unix.AF_INET, netip.IPv4Unspecified(), netip.IPv4Unspecified(), 5000, 0, 1003, 333),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerB}, true)
		if err != nil || uid != 1003 || inode != 333 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1003, 333, nil", uid, inode, err)
		}
	})

	t.Run("falls back to matching source when peer differs (REDIR)", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, src, peerA.Addr(), 5000, 443, 1001, 111),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7892")}, false)
		if err != nil || uid != 1001 || inode != 111 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1001, 111, nil", uid, inode, err)
		}
	})

	// Unconnected UDP sockets report a wildcard source in INET_DIAG unless
	// the program bound one.
	t.Run("finds wildcard unconnected IPv4 UDP socket", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, netip.IPv4Unspecified(), netip.IPv4Unspecified(), 5000, 0, 1004, 444),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerA}, true)
		if err != nil || uid != 1004 || inode != 444 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1004, 444, nil", uid, inode, err)
		}
	})

	t.Run("finds wildcard unconnected IPv6 UDP socket", func(t *testing.T) {
		src6 := netip.MustParseAddr("fd00::1")
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET6, netip.IPv6Unspecified(), netip.IPv6Unspecified(), 5000, 0, 1005, 555),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src6, 5000, []netip.AddrPort{netip.MustParseAddrPort("[2600::]:443")}, true)
		if err != nil || uid != 1005 || inode != 555 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1005, 555, nil", uid, inode, err)
		}
	})

	t.Run("bound unconnected UDP beats wildcard in either order", func(t *testing.T) {
		bound := diagMessage(unix.AF_INET, src, netip.IPv4Unspecified(), 5000, 0, 1006, 666)
		wildcard := diagMessage(unix.AF_INET, netip.IPv4Unspecified(), netip.IPv4Unspecified(), 5000, 0, 1007, 777)
		for _, msgs := range [][]netlink.Message{{bound, wildcard}, {wildcard, bound}} {
			uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerB}, true)
			if err != nil || uid != 1006 || inode != 666 {
				t.Fatalf("got uid=%d inode=%d err=%v; want 1006, 666, nil", uid, inode, err)
			}
		}
	})

	// A TCP entry with an unspecified destination is a listener on the port.
	t.Run("TCP listener loses to established socket in either order", func(t *testing.T) {
		listener := diagMessage(unix.AF_INET, src, netip.IPv4Unspecified(), 5000, 0, 1008, 888)
		established := diagMessage(unix.AF_INET, src, netip.MustParseAddr("9.9.9.9"), 5000, 80, 1009, 999)
		for _, msgs := range [][]netlink.Message{{listener, established}, {established, listener}} {
			uid, inode, err := matchInetDiagResponses(msgs, src, 5000, []netip.AddrPort{peerA}, false)
			if err != nil || uid != 1009 || inode != 999 {
				t.Fatalf("got uid=%d inode=%d err=%v; want 1009, 999, nil", uid, inode, err)
			}
		}
	})

	t.Run("without peers bound socket beats wildcard UDP", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, netip.IPv4Unspecified(), netip.IPv4Unspecified(), 5000, 0, 1003, 333),
			diagMessage(unix.AF_INET, src, netip.IPv4Unspecified(), 5000, 0, 1004, 444),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, nil, true)
		if err != nil || uid != 1004 || inode != 444 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1004, 444, nil", uid, inode, err)
		}
	})

	t.Run("without peers falls back to wildcard unconnected UDP", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, netip.IPv4Unspecified(), netip.IPv4Unspecified(), 5000, 0, 1007, 777),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, nil, true)
		if err != nil || uid != 1007 || inode != 777 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 1007, 777, nil", uid, inode, err)
		}
	})

	t.Run("ignores wildcard UDP socket with a peer", func(t *testing.T) {
		msgs := []netlink.Message{
			diagMessage(unix.AF_INET, netip.IPv4Unspecified(), peerA.Addr(), 5000, 443, 1010, 1010),
		}
		uid, inode, err := matchInetDiagResponses(msgs, src, 5000, nil, true)
		if !errors.Is(err, ErrNotFound) || uid != 0 || inode != 0 {
			t.Fatalf("got uid=%d inode=%d err=%v; want 0, 0, ErrNotFound", uid, inode, err)
		}
	})
}
