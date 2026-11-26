package process

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These sizes and offsets are socketowner ABI v1, independently specified in
// socketowner/docs/map-interface.md. Check Go padding on every reader target.
func TestSockOwnerABILayout(t *testing.T) {
	for name, tc := range map[string]struct{ got, want uintptr }{
		"key size":    {unsafe.Sizeof(sockOwnerKey{}), 32},
		"key netns":   {unsafe.Offsetof(sockOwnerKey{}.Netns), 0},
		"key addr":    {unsafe.Offsetof(sockOwnerKey{}.Addr), 8},
		"key port":    {unsafe.Offsetof(sockOwnerKey{}.Port), 24},
		"key proto":   {unsafe.Offsetof(sockOwnerKey{}.Proto), 26},
		"owner size":  {unsafe.Sizeof(sockOwnerValue{}), 16},
		"owner tgid":  {unsafe.Offsetof(sockOwnerValue{}.Tgid), 0},
		"owner uid":   {unsafe.Offsetof(sockOwnerValue{}.UID), 4},
		"owner time":  {unsafe.Offsetof(sockOwnerValue{}.BootNs), 8},
		"exec size":   {unsafe.Sizeof(execPathValue{}), 1048},
		"exec start":  {unsafe.Offsetof(execPathValue{}.StartNs), 0},
		"exec exit":   {unsafe.Offsetof(execPathValue{}.ExitNs), 8},
		"exec length": {unsafe.Offsetof(execPathValue{}.Len), 16},
		"exec path":   {unsafe.Offsetof(execPathValue{}.Path), 24},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", name, tc.got, tc.want)
		}
	}
}

func TestNewSockOwnerKey(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	for network, want := range map[string]uint8{
		"tcp":     unix.IPPROTO_TCP,
		"tcp4":    unix.IPPROTO_TCP,
		"udp":     unix.IPPROTO_UDP,
		"udp6":    unix.IPPROTO_UDP,
		"unix":    0,
		"invalid": 0,
	} {
		key, ok := newSockOwnerKey(network, ip, 1234)
		if network == "unix" || network == "invalid" {
			if ok {
				t.Errorf("%s: got key %+v, want no key", network, key)
			}
			continue
		}
		if !ok || key.Proto != want || key.Port != 1234 || key.Addr != ip.As16() {
			t.Errorf("%s: got key %+v, ok %v", network, key, ok)
		}
	}
}

func TestExecPathDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    execPathValue
		want string
	}{
		{name: "errno", v: execPathValue{Len: -int32(unix.ENOENT)}},
		{name: "empty", v: execPathValue{Len: 0}},
		{name: "nul only", v: execPathValue{Len: 1}},
		{name: "path", v: execPathValue{Len: int32(len("/bin/sh") + 1)}, want: "/bin/sh"},
		{name: "too long", v: execPathValue{Len: int32(len(execPathValue{}.Path) + 1)}},
	} {
		copy(tc.v.Path[:], "/bin/sh\x00")
		got, err := tc.v.execPath()
		if tc.want != "" {
			if err != nil || got != tc.want {
				t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
			}
			continue
		}
		if err == nil || errors.Is(err, errSockOwnerGone) {
			t.Errorf("%s: got %q, %v; want a malformed-record error", tc.name, got, err)
		}
	}
}

func TestSockOwnerPathFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"reused pid", errSockOwnerGone, false},
		{"nested pid namespace", errNotInitialPidNS, false},
		{"exec path decode error", fmt.Errorf("executable of process 1: %w: %w", errSockOwnerExec, unix.ENAMETOOLONG), false},
		{"no record", ErrNotFound, true},
	} {
		if got := sockOwnerPathFallback(tc.err); got != tc.want {
			t.Errorf("%s: fallback %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsInitialPidNamespace(t *testing.T) {
	for link, want := range map[string]bool{
		"pid:[4026531836]": true,
		"pid:[4026532001]": false,
		"pid:[4026531836":  false,
		"":                 false,
	} {
		if got := isInitialPidNamespace(link); got != want {
			t.Errorf("%q: got %v, want %v", link, got, want)
		}
	}
}

// A pin that disappears clears the last warning, so the same open error is
// reported when the pin comes back with it.
func TestPinnedMapSetWarnsAgainAfterMissingPin(t *testing.T) {
	var p pinnedMapSet
	openErr := errors.New("unexpected map layout")
	if !p.warnOnce(openErr) {
		t.Fatal("the first warning was suppressed")
	}
	if p.warnOnce(openErr) {
		t.Fatal("the repeated warning was not suppressed")
	}
	closed := 0
	changed, err := p.refresh(filepath.Join(t.TempDir(), "missing_pin"), func() { closed++ }, func() error {
		t.Fatal("opened a missing pin")
		return nil
	})
	if err != nil || changed {
		t.Fatalf("refresh of a missing pin: changed %v, err %v", changed, err)
	}
	if closed != 1 {
		t.Fatalf("closed %d times, want 1", closed)
	}
	if !p.warnOnce(openErr) {
		t.Fatal("the warning stayed suppressed after the pin disappeared")
	}
}

func TestParseProcStatStartTicks(t *testing.T) {
	// comm can contain spaces and parentheses; starttime is field 22.
	stat := "123 (foo (bar) ) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20 21\n"
	got, err := parseProcStatStartTicks([]byte(stat))
	if err != nil || got != 987 {
		t.Fatalf("got %d, %v; want 987", got, err)
	}
	for name, stat := range map[string]string{
		"no comm":    "123 1 2 3",
		"short":      "123 (foo) S 1 2 3",
		"not a tick": "123 (foo) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 x 20",
	} {
		if _, err := parseProcStatStartTicks([]byte(stat)); err == nil {
			t.Errorf("%s: parsed %q", name, stat)
		}
	}
}

func TestReadSockOwnerExeCurrentProcess(t *testing.T) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	owner := sockOwnerValue{Tgid: uint32(os.Getpid()), BootNs: uint64(now.Nano())}
	exe, err := readSockOwnerExe(owner)
	if err != nil || exe == "" {
		t.Fatalf("own process: %q, %v", exe, err)
	}
	// A process that started later than the owner record reused the ID.
	owner.BootNs = 1
	if _, err := readSockOwnerExe(owner); !errors.Is(err, errSockOwnerGone) {
		t.Fatalf("reused PID: got %v, want %v", err, errSockOwnerGone)
	}
}

func TestReadSockOwnerExeStatErrors(t *testing.T) {
	owner := sockOwnerValue{Tgid: 42}
	readlink := func(string) (string, error) { return "/bin/foo", nil }
	for name, tc := range map[string]struct {
		statErr error
		want    string
		wantErr error
	}{
		"eacces": {statErr: unix.EACCES, want: "/bin/foo"},
		"eperm":  {statErr: unix.EPERM, want: "/bin/foo"},
		"enoent": {statErr: unix.ENOENT, wantErr: errSockOwnerGone},
	} {
		readFile := func(string) ([]byte, error) { return nil, tc.statErr }
		got, err := readSockOwnerExeAt(owner, "/proc", readlink, readFile)
		if got != tc.want || (tc.wantErr == nil) != (err == nil) {
			t.Errorf("%s: got %q, %v; want %q, %v", name, got, err, tc.want, tc.wantErr)
			continue
		}
		if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: got %v, want %v", name, err, tc.wantErr)
		}
	}
}
