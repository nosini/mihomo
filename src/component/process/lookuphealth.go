package process

// Health is a snapshot of process lookup through the pinned BPF maps, served
// by the external controller's /process-lookup route. Counters grow from
// process start and are never reset. See docs/socketowner.md.
type Health struct {
	// Supported is false on builds without the Linux BPF reader; Message
	// then says so and nothing else is filled in.
	Supported bool   `json:"supported"`
	Message   string `json:"message,omitempty"`
	// BPFOnly mirrors find-process-bpf-only: lookup never reads /proc.
	BPFOnly bool `json:"bpfOnly"`
	// MapPath is the configured socket-owner map, empty when BPF lookup is
	// disabled.
	MapPath  string       `json:"mapPath"`
	Maps     MapsHealth   `json:"maps"`
	Wine     WineHealth   `json:"wine"`
	Cgroups  CgroupHealth `json:"cgroups"`
	Counters Counters     `json:"counters"`
}

// MapsHealth reports the socket-owner maps the reader uses.
type MapsHealth struct {
	// Open is true while the socket-owner map is open.
	Open bool `json:"open"`
	// AbiVersion is the map interface version the open map was validated
	// against; 0 while it is closed.
	AbiVersion uint32 `json:"abiVersion"`
	// Error is the last error from opening or validating the maps, such as
	// an unsupported ABI version. It is empty while they are open, and also
	// when nothing is pinned at the configured path yet.
	Error string `json:"error,omitempty"`
	// ExecMapsOpen is true while the exec-path maps are open beside the
	// socket-owner map, so executable paths are resolved without /proc.
	ExecMapsOpen bool `json:"execMapsOpen"`
	// ExecMapsError is the last error from opening the exec-path maps;
	// empty while they are open.
	ExecMapsError string `json:"execMapsError,omitempty"`
}

// CgroupHealth reports attribution of connections to the owner's cgroup,
// which FLATPAK-APP and SYSTEMD-UNIT rules use.
type CgroupHealth struct {
	// Available is true while the owner-cgroup map is open and cgroups can
	// be named: from the loader's cgroup paths, or else from cgroupfs, which
	// could be read the last time.
	Available bool `json:"available"`
	// MapOpen is true while the loader's owner-cgroup map is open.
	MapOpen bool `json:"mapOpen"`
	// PathsMapOpen is true while the loader's cgroup paths are open; they
	// are recorded with -exec-paths.
	PathsMapOpen bool `json:"pathsMapOpen"`
	// MapError says why the maps aren't open, such as a loader that doesn't
	// publish them; empty while they are or the socket-owner map is closed.
	MapError string `json:"mapError,omitempty"`
	// Source is where cgroups are named: "bpf" for the loader's paths,
	// "cgroupfs" for a listing of Root.
	Source string `json:"source"`
	// Root is the cgroupfs mount cgroup IDs are resolved in, when Source is
	// cgroupfs.
	Root string `json:"root,omitempty"`
	// KnownCgroups is the number of cgroups found in the last walk of Root.
	KnownCgroups int `json:"knownCgroups,omitempty"`
	// RootError is the error from the last walk of Root, if it failed.
	RootError string `json:"rootError,omitempty"`
}

// WineHealth reports the Wine observer's maps and heartbeat.
type WineHealth struct {
	// Present is true while the Wine maps are open.
	Present bool `json:"present"`
	// AbiVersion is the Wine map version the open maps were validated
	// against; 0 while they are absent.
	AbiVersion uint32 `json:"abiVersion"`
	// HeartbeatAgeSeconds is the age of the observer's heartbeat, truncated
	// to whole seconds. It is left out when the heartbeat can't be read, and
	// is negative when the heartbeat is ahead of the boot clock, which the
	// reader treats as stale.
	HeartbeatAgeSeconds *int64 `json:"heartbeatAgeSeconds,omitempty"`
	// Stale is true while the maps are present and the heartbeat counts as
	// stale, by the reader's five-second limit.
	Stale bool `json:"stale"`
}

// Counters count process lookups since start. BPF hits and misses cover the
// lookups that consulted the maps; every other lookup went through netlink
// and the /proc search.
type Counters struct {
	BPFHits          uint64 `json:"bpfHits"`
	BPFMisses        uint64 `json:"bpfMisses"`
	ProcFallbacks    uint64 `json:"procFallbacks"`
	WineKnown        uint64 `json:"wineKnown"`
	WineUnknown      uint64 `json:"wineUnknown"`
	WineStaleRefused uint64 `json:"wineStaleRefused"`
	// CgroupKnown and CgroupUnknown count cgroup lookups that named a
	// cgroup and those that didn't.
	CgroupKnown   uint64 `json:"cgroupKnown"`
	CgroupUnknown uint64 `json:"cgroupUnknown"`
}

// LookupHealth returns the snapshot for the /process-lookup route.
func LookupHealth() *Health {
	return lookupHealth()
}
