package process

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

// DefaultSockOwnerMap is where the independently installed socketowner loader
// pins the map used on Linux. See docs/socketowner.md.
const DefaultSockOwnerMap = "/sys/fs/bpf/mihomo/maps/conn_owners"

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (uint32, string, error) {
	return findProcessName(network, srcIP, srcPort)
}

// ProcessBaseName returns the name of a process path from FindProcessName.
// Windows images keep their backslashes, which filepath.Base doesn't split on
// Linux, and rules name them like any other process.
func ProcessBaseName(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return filepath.Base(path)
}

// PackageNameResolver
// never change type traits because it's used in CMFA
type PackageNameResolver func(metadata *C.Metadata) (string, error)

// DefaultPackageNameResolver
// never change type traits because it's used in CMFA
var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *C.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}
