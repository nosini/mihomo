package process

import (
	"errors"
	"fmt"
	"net/netip"
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
