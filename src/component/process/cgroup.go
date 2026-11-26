package process

import (
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
)

// FindCgroup returns the cgroup v2 path, relative to the cgroupfs root, of
// the process that owns a connection, as recorded by socketowner. ok is false
// when the owner or its cgroup is unknown, including a cgroup that was removed
// before the lookup. peers are the destinations the connection's outgoing
// packets may carry, as for FindProcessName. See docs/socketowner.md.
func FindCgroup(network string, srcIP netip.Addr, srcPort int, peers ...netip.AddrPort) (path string, ok bool) {
	return findCgroup(network, srcIP, srcPort, peers)
}

// cgroupLookupWanted is set once a rule needs cgroups, so that a loader
// without them is reported to those who rely on it only.
var cgroupLookupWanted atomic.Bool

// WantCgroupLookup marks cgroup attribution as needed by a rule. When it is
// unavailable, the next lookup logs one warning.
func WantCgroupLookup() {
	cgroupLookupWanted.Store(true)
}

// The prefixes and suffix of the transient scopes flatpak run starts for an
// app: app-flatpak-<app ID>-<instance>.scope, or flatpak-<app ID>-<PID>.scope
// from earlier Flatpak versions.
const (
	flatpakScopePrefix       = "app-flatpak-"
	legacyFlatpakScopePrefix = "flatpak-"
	flatpakScopeSuffix       = ".scope"
)

// FlatpakAppFromCgroupPath returns the Flatpak app ID of a cgroup path. Only
// the nearest component named like a Flatpak scope counts: the cgroup itself
// or the closest ancestor. When that component isn't a valid scope name, the
// app is unknown rather than taken from a component further up.
func FlatpakAppFromCgroupPath(path string) (string, bool) {
	for path != "" {
		i := strings.LastIndexByte(path, '/')
		name := path[i+1:]
		if i < 0 {
			path = ""
		} else {
			path = path[:i]
		}
		if strings.HasPrefix(name, flatpakScopePrefix) ||
			(strings.HasPrefix(name, legacyFlatpakScopePrefix) && strings.HasSuffix(name, flatpakScopeSuffix)) {
			return ParseFlatpakScope(name)
		}
	}
	return "", false
}

// ParseFlatpakScope returns the app ID of a scope named by flatpak run:
// app-flatpak-<escaped app ID>-<instance ID>.scope from Flatpak 1.11 and later,
// with the app ID escaped as a systemd unit name (a "-" becomes \x2d) and a
// decimal instance ID, or flatpak-<app ID>-<PID>.scope from earlier versions.
// Both forms end in "-<digits>", which is split at the last "-".
func ParseFlatpakScope(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, flatpakScopePrefix)
	if !ok {
		if rest, ok = strings.CutPrefix(name, legacyFlatpakScopePrefix); !ok {
			return "", false
		}
	}
	if rest, ok = strings.CutSuffix(rest, flatpakScopeSuffix); !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, '-')
	if i < 0 || !allDigits(rest[i+1:]) {
		return "", false
	}
	id, ok := unescapeUnitName(rest[:i])
	if !ok || !ValidFlatpakAppID(id) {
		return "", false
	}
	return id, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// unescapeUnitName reverses systemd's \xNN escaping of unit name characters.
func unescapeUnitName(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) || s[i+1] != 'x' {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), true
}

// ValidFlatpakAppID reports whether id is a valid Flatpak application ID, by
// the rules of flatpak_is_valid_name: at most 255 characters, three or more
// non-empty elements separated by ".", each of [A-Za-z0-9_-] and not starting
// with a digit, with "-" only in the last element.
func ValidFlatpakAppID(id string) bool {
	if id == "" || len(id) > 255 {
		return false
	}
	elements := strings.Split(id, ".")
	if len(elements) < 3 {
		return false
	}
	for n, e := range elements {
		last := n == len(elements)-1
		if e == "" {
			return false
		}
		for i := 0; i < len(e); i++ {
			c := e[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
			case c >= '0' && c <= '9' && i > 0:
			case c == '-' && last:
			default:
				return false
			}
		}
	}
	return true
}

// SystemdUnitFromCgroupPath returns the systemd service or scope whose cgroup
// holds path: the cgroup itself or its nearest ancestor named like one. Slices
// only group units, and the cgroups below a unit's own (a container's
// libpod-payload-… or runtime, say) belong to that unit. The name is returned
// as systemd spells it, escapes included.
func SystemdUnitFromCgroupPath(path string) (string, bool) {
	for path != "" {
		i := strings.LastIndexByte(path, '/')
		name := path[i+1:]
		if i < 0 {
			path = ""
		} else {
			path = path[:i]
		}
		if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".scope") {
			if !ValidSystemdUnitName(name) {
				return "", false
			}
			return name, true
		}
	}
	return "", false
}

// ValidSystemdUnitName reports whether name is a valid systemd service or
// scope name which can have a cgroup, by the rules of unit_name_is_valid: at
// most 255 characters of [A-Za-z0-9:_.\-] before the suffix, a non-empty
// prefix, and at most one "@" followed by a non-empty instance. A template
// such as getty@.service has no cgroup of its own.
func ValidSystemdUnitName(name string) bool {
	if len(name) > 255 {
		return false
	}
	stem, ok := strings.CutSuffix(name, ".service")
	if !ok {
		if stem, ok = strings.CutSuffix(name, ".scope"); !ok {
			return false
		}
	}
	prefix, instance, templated := strings.Cut(stem, "@")
	if prefix == "" || templated && instance == "" {
		return false
	}
	for _, part := range []string{prefix, instance} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == ':', c == '_', c == '.', c == '-', c == '\\':
			default:
				return false
			}
		}
	}
	return true
}
