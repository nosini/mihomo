//go:build !linux

package process

var sockOwnerMapPath = DefaultSockOwnerMap

// SetSockOwnerMap sets the pinned socket-owner map to use. The map is only
// used on Linux.
func SetSockOwnerMap(path string) { sockOwnerMapPath = path }

// SockOwnerMap returns the configured map path.
func SockOwnerMap() string { return sockOwnerMapPath }
