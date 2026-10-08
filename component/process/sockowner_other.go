//go:build !linux

package process

var sockOwnerMapPath = DefaultSockOwnerMap

// SetSockOwnerMap sets the pinned socket-owner map to use. The map is only
// used on Linux.
func SetSockOwnerMap(path string) { sockOwnerMapPath = path }

// SockOwnerMap returns the configured map path.
func SockOwnerMap() string { return sockOwnerMapPath }

var sockOwnerOnly bool

// SetSockOwnerOnly sets whether process lookup uses the BPF maps alone, which
// only exist on Linux.
func SetSockOwnerOnly(only bool) { sockOwnerOnly = only }

// SockOwnerOnly reports whether process lookup uses the BPF maps alone.
func SockOwnerOnly() bool { return sockOwnerOnly }
