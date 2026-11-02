package process

import (
	"testing"
	"unsafe"
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
