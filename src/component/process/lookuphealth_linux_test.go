package process

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWinePublicationState(t *testing.T) {
	for name, tc := range map[string]struct {
		open, beatRead bool
		age            time.Duration
		want           wineState
	}{
		"closed":           {open: false, want: wineStateAbsent},
		"closed with beat": {open: false, beatRead: true, want: wineStateAbsent},
		"fresh":            {open: true, beatRead: true, age: time.Second, want: wineStateLive},
		"just fresh":       {open: true, beatRead: true, age: wineHeartbeatLimit - 1, want: wineStateLive},
		"unreadable":       {open: true, want: wineStateStale},
		"beat from future": {open: true, beatRead: true, age: -time.Second, want: wineStateStale},
		"at the limit":     {open: true, beatRead: true, age: wineHeartbeatLimit, want: wineStateStale},
		"long dead":        {open: true, beatRead: true, age: time.Minute, want: wineStateStale},
	} {
		if got := winePublicationState(tc.open, tc.beatRead, tc.age); got != tc.want {
			t.Errorf("%s: got state %d, want %d", name, got, tc.want)
		}
	}
}

func TestWineTransition(t *testing.T) {
	for _, tc := range []struct {
		from, to wineState
		warn     bool
		message  string // the distinctive words, empty when nothing is logged
	}{
		{from: wineStateUnknown, to: wineStateUnknown},
		{from: wineStateUnknown, to: wineStateAbsent},
		{from: wineStateUnknown, to: wineStateLive},
		{from: wineStateUnknown, to: wineStateStale, warn: true, message: "stale"},
		{from: wineStateAbsent, to: wineStateAbsent},
		{from: wineStateAbsent, to: wineStateLive, message: "are back"},
		{from: wineStateAbsent, to: wineStateStale, warn: true, message: "stale"},
		{from: wineStateLive, to: wineStateLive},
		{from: wineStateLive, to: wineStateAbsent, warn: true, message: "disappeared"},
		{from: wineStateLive, to: wineStateStale, warn: true, message: "stale"},
		{from: wineStateStale, to: wineStateLive, message: "fresh again"},
		{from: wineStateStale, to: wineStateStale},
		{from: wineStateStale, to: wineStateAbsent, warn: true, message: "disappeared"},
	} {
		message, warn := wineTransition(tc.from, tc.to, "/run/mihomo-bpf")
		if tc.message == "" {
			if message != "" {
				t.Errorf("%d to %d: logged %q, want nothing", tc.from, tc.to, message)
			}
			continue
		}
		if warn != tc.warn || !strings.Contains(message, tc.message) || !strings.Contains(message, "/run/mihomo-bpf") {
			t.Errorf("%d to %d: %q warn %v, want a %q message naming the directory",
				tc.from, tc.to, message, warn, tc.message)
		}
	}
}

func TestWineHealthSnapshot(t *testing.T) {
	health := wineHealth(wineStateAbsent, 0, false)
	if health.Present || health.AbiVersion != 0 || health.Stale || health.HeartbeatAgeSeconds != nil {
		t.Fatalf("absent: %+v", health)
	}
	health = wineHealth(wineStateLive, 1500*time.Millisecond, true)
	if !health.Present || health.AbiVersion != wineABIVersion || health.Stale {
		t.Fatalf("live: %+v", health)
	}
	if age := health.HeartbeatAgeSeconds; age == nil || *age != 1 {
		t.Fatalf("live: heartbeat age %+v, want 1", health.HeartbeatAgeSeconds)
	}
	health = wineHealth(wineStateStale, 0, false)
	if !health.Present || !health.Stale || health.HeartbeatAgeSeconds != nil {
		t.Fatalf("unreadable heartbeat: %+v", health)
	}
	health = wineHealth(wineStateStale, -90*time.Second, true)
	if !health.Stale || health.HeartbeatAgeSeconds == nil || *health.HeartbeatAgeSeconds != -90 {
		t.Fatalf("beat ahead of the clock: %+v", health)
	}
}

// swapLookups replaces the lookup globals for a test and restores them.
func swapLookups(t *testing.T, owners *sockOwnerMap, wine *wineFlows) {
	t.Helper()
	previousOwners, previousWine := sockOwners, wineFlowMaps
	sockOwners, wineFlowMaps = owners, wine
	t.Cleanup(func() { sockOwners, wineFlowMaps = previousOwners, previousWine })
}

// resetLookupCounters zeroes the counters, which other tests may have grown.
func resetLookupCounters(t *testing.T) {
	t.Helper()
	lookupCounters.bpfHits.Store(0)
	lookupCounters.bpfMisses.Store(0)
	lookupCounters.procFallbacks.Store(0)
	lookupCounters.wineKnown.Store(0)
	lookupCounters.wineUnknown.Store(0)
	lookupCounters.wineStaleRefused.Store(0)
}

// freshPins leaves publication points that were just checked, so a snapshot
// reads the state below without opening anything.
func freshPins(now time.Time) (pinnedMapSet, pinnedMapSet) {
	return pinnedMapSet{checkedAt: now}, pinnedMapSet{checkedAt: now}
}

func TestLookupHealth(t *testing.T) {
	ownerPin, winePin := freshPins(time.Now())
	owners := &sockOwnerMap{
		path:     "/run/mihomo-bpf/conn_owners",
		only:     true,
		fd:       3,
		tasksFd:  4,
		recentFd: 5,
		pinned:   ownerPin,
	}
	wine := &wineFlows{flowsFd: -1, heartbeatFd: -1, pinned: winePin}
	swapLookups(t, owners, wine)
	resetLookupCounters(t)
	lookupCounters.bpfHits.Add(21)
	lookupCounters.procFallbacks.Add(2)

	h := LookupHealth()
	if !h.Supported || h.Message != "" {
		t.Fatalf("supported %v, message %q", h.Supported, h.Message)
	}
	if !h.BPFOnly || h.MapPath != owners.path {
		t.Fatalf("bpfOnly %v, mapPath %q", h.BPFOnly, h.MapPath)
	}
	if !h.Maps.Open || h.Maps.AbiVersion != sockOwnerABIVersion || h.Maps.Error != "" {
		t.Fatalf("maps: %+v", h.Maps)
	}
	if !h.Maps.ExecMapsOpen || h.Maps.ExecMapsError != "" {
		t.Fatalf("exec-path maps: %+v", h.Maps)
	}
	if h.Wine.Present || h.Wine.Stale || h.Wine.AbiVersion != 0 || h.Wine.HeartbeatAgeSeconds != nil {
		t.Fatalf("wine: %+v", h.Wine)
	}
	if h.Counters.BPFHits != 21 || h.Counters.BPFMisses != 0 || h.Counters.ProcFallbacks != 2 {
		t.Fatalf("counters: %+v", h.Counters)
	}
	if h.Counters.WineKnown != 0 || h.Counters.WineUnknown != 0 || h.Counters.WineStaleRefused != 0 {
		t.Fatalf("wine counters: %+v", h.Counters)
	}
}

func TestLookupHealthClosedMaps(t *testing.T) {
	ownerPin, winePin := freshPins(time.Now())
	owners := &sockOwnerMap{
		path:     "/run/mihomo-bpf/conn_owners",
		fd:       -1,
		tasksFd:  -1,
		recentFd: -1,
		pinned:   ownerPin,
		openErr:  "socketowner ABI (install a compatible socketowner loader): unsupported ABI v2 in /run/mihomo-bpf/abi_version (need v1)",
		execErr:  "open /run/mihomo-bpf/exec_tasks: no such file or directory",
	}
	wine := &wineFlows{flowsFd: -1, heartbeatFd: -1, pinned: winePin}
	swapLookups(t, owners, wine)

	h := LookupHealth()
	if h.Maps.Open || h.Maps.AbiVersion != 0 || h.Maps.Error != owners.openErr {
		t.Fatalf("maps: %+v", h.Maps)
	}
	if h.Maps.ExecMapsOpen || h.Maps.ExecMapsError != owners.execErr {
		t.Fatalf("exec-path maps: %+v", h.Maps)
	}
	if h.Wine.Present {
		t.Fatalf("wine: %+v", h.Wine)
	}
}

func TestLookupHealthDisabled(t *testing.T) {
	ownerPin, _ := freshPins(time.Now())
	owners := &sockOwnerMap{path: "", fd: -1, tasksFd: -1, recentFd: -1, pinned: ownerPin}
	swapLookups(t, owners, &wineFlows{flowsFd: -1, heartbeatFd: -1})

	h := LookupHealth()
	if h.MapPath != "" || h.Maps.Open || h.Maps.Error != "" || h.Wine.Present {
		t.Fatalf("disabled lookup: %+v", h)
	}
}

// A lookup against an open fd that is no BPF map counts as a miss; the maps
// were consulted and answered nothing.
func TestLookupSockOwnerCountsMiss(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	ownerPin, _ := freshPins(time.Now())
	swapLookups(t, &sockOwnerMap{
		path:     "/run/mihomo-bpf/conn_owners",
		fd:       fd,
		tasksFd:  -1,
		recentFd: -1,
		netns:    1,
		pinned:   ownerPin,
	}, wineFlowMaps)
	resetLookupCounters(t)

	if _, ok := lookupSockOwner("tcp", netip.MustParseAddr("127.0.0.1"), 4242); ok {
		t.Fatal("an ordinary socket named an owner")
	}
	if hits, misses := lookupCounters.bpfHits.Load(), lookupCounters.bpfMisses.Load(); hits != 0 || misses != 1 {
		t.Fatalf("hits %d, misses %d, want 0 and 1", hits, misses)
	}
}

func TestNoteWineHealth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conn_owners")
	wine := &wineFlows{flowsFd: -1, heartbeatFd: -1}
	previous := wineFlowMaps
	wineFlowMaps = wine
	t.Cleanup(func() { wineFlowMaps = previous })

	// The pins are absent, so the first sample records that quietly.
	noteWineHealth(dir)
	if got := wineState(wine.healthState.Load()); got != wineStateAbsent {
		t.Fatalf("state %d, want absent", got)
	}
	checked := wine.healthChecked.Load()
	if checked == 0 {
		t.Fatal("the check was not recorded")
	}
	// Inside the limit nothing is sampled again.
	noteWineHealth(dir)
	if wine.healthChecked.Load() != checked {
		t.Fatal("sampled again inside the limit")
	}
	// A config change forgets the state, so the next sample is a first
	// observation that logs nothing.
	wine.reset()
	if got := wineState(wine.healthState.Load()); got != wineStateUnknown {
		t.Fatalf("state after reset %d, want unknown", got)
	}
}

func TestHealthJSON(t *testing.T) {
	// The response documented in docs/socketowner.md.
	age := int64(1)
	h := &Health{
		Supported: true,
		BPFOnly:   false,
		MapPath:   "/run/mihomo-bpf/conn_owners",
		Maps: MapsHealth{
			Open:         true,
			AbiVersion:   sockOwnerABIVersion,
			ExecMapsOpen: true,
		},
		Wine: WineHealth{
			Present:             true,
			AbiVersion:          wineABIVersion,
			HeartbeatAgeSeconds: &age,
		},
		Cgroups: CgroupHealth{
			Available:    true,
			MapOpen:      true,
			Root:         "/sys/fs/cgroup",
			KnownCgroups: 143,
		},
		Counters: Counters{BPFHits: 21, BPFMisses: 3, ProcFallbacks: 2, WineKnown: 5, WineUnknown: 1, CgroupKnown: 4, CgroupUnknown: 17},
	}
	got, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"supported":true,"bpfOnly":false,"mapPath":"/run/mihomo-bpf/conn_owners",` +
		`"maps":{"open":true,"abiVersion":1,"execMapsOpen":true},` +
		`"wine":{"present":true,"abiVersion":2,"heartbeatAgeSeconds":1,"stale":false},` +
		`"cgroups":{"available":true,"mapOpen":true,"root":"/sys/fs/cgroup","knownCgroups":143},` +
		`"counters":{"bpfHits":21,"bpfMisses":3,"procFallbacks":2,"wineKnown":5,"wineUnknown":1,"wineStaleRefused":0,` +
		`"cgroupKnown":4,"cgroupUnknown":17}}`
	if string(got) != want {
		t.Fatalf("got:\n%s", got)
	}
}
