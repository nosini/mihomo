package process

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

// lookupCounters grow on the lookup path, which takes no lock for them; only
// the health snapshot reads them back.
var lookupCounters struct {
	bpfHits          atomic.Uint64
	bpfMisses        atomic.Uint64
	procFallbacks    atomic.Uint64
	wineKnown        atomic.Uint64
	wineUnknown      atomic.Uint64
	wineStaleRefused atomic.Uint64
	cgroupKnown      atomic.Uint64
	cgroupUnknown    atomic.Uint64
}

// lookupHealth returns the state of process lookup through the BPF maps.
// Publication points that haven't been checked recently are refreshed, so the
// snapshot reflects the current pins even before any lookup has run.
func lookupHealth() *Health {
	h := &Health{
		Supported: true,
		BPFOnly:   SockOwnerOnly(),
		MapPath:   SockOwnerMap(),
	}
	h.Maps = sockOwners.mapsHealth()
	h.Cgroups = sockOwners.cgroupHealth()
	if dir, ok := wineFlowsDir(h.MapPath); ok {
		state, age, beatRead := wineFlowMaps.sampleHealth(dir)
		h.Wine = wineHealth(state, age, beatRead)
	}
	h.Counters = Counters{
		BPFHits:          lookupCounters.bpfHits.Load(),
		BPFMisses:        lookupCounters.bpfMisses.Load(),
		ProcFallbacks:    lookupCounters.procFallbacks.Load(),
		WineKnown:        lookupCounters.wineKnown.Load(),
		WineUnknown:      lookupCounters.wineUnknown.Load(),
		WineStaleRefused: lookupCounters.wineStaleRefused.Load(),
		CgroupKnown:      lookupCounters.cgroupKnown.Load(),
		CgroupUnknown:    lookupCounters.cgroupUnknown.Load(),
	}
	return h
}

// mapsHealth reports the socket-owner maps for a health snapshot, refreshing
// a publication point that hasn't been checked recently the way a lookup miss
// does.
func (m *sockOwnerMap) mapsHealth() MapsHealth {
	m.mu.RLock()
	stale := m.pinned.stale()
	m.mu.RUnlock()
	if stale {
		m.mu.Lock()
		if m.pinned.stale() {
			m.refreshLocked()
		}
		m.mu.Unlock()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	health := MapsHealth{
		Open:          m.fd >= 0,
		Error:         m.openErr,
		ExecMapsOpen:  m.tasksFd >= 0,
		ExecMapsError: m.execErr,
	}
	if health.Open {
		health.AbiVersion = sockOwnerABIVersion
	}
	return health
}

// The Wine publication states, remembered between checks so that a change is
// logged once.
type wineState int32

const (
	// wineStateUnknown is a fresh reader or a changed map path; the next
	// sample counts as a first observation and logs nothing for most states.
	wineStateUnknown wineState = iota
	wineStateAbsent
	wineStateLive
	wineStateStale
)

// wineTransition returns the log line for a change of the Wine publication
// state, empty when the change needs none. warn marks a warning. A state
// repeated is not a change and logs nothing.
func wineTransition(from, to wineState, dir string) (message string, warn bool) {
	switch {
	case to == wineStateStale && from != wineStateStale:
		return fmt.Sprintf("Wine heartbeat in %s is stale; covered flows match as wine-unknown", dir), true
	case to == wineStateAbsent && from != wineStateUnknown && from != wineStateAbsent:
		return fmt.Sprintf("Wine maps in %s disappeared; WINE-PROCESS rules match nothing until they return", dir), true
	case to == wineStateLive && from == wineStateAbsent:
		return fmt.Sprintf("Wine maps in %s are back; the heartbeat is fresh", dir), false
	case to == wineStateLive && from == wineStateStale:
		return fmt.Sprintf("Wine heartbeat in %s is fresh again", dir), false
	}
	return "", false
}

// winePublicationState classifies the Wine publication point. The publisher
// writes host CLOCK_BOOTTIME, so a beat from the future means another clock
// (a time namespace) and proves nothing. A heartbeat that can't be read
// counts as stale: the lookup refuses to trust its records the same way.
func winePublicationState(open, beatRead bool, age time.Duration) wineState {
	switch {
	case !open:
		return wineStateAbsent
	case beatRead && age >= 0 && age < wineHeartbeatLimit:
		return wineStateLive
	}
	return wineStateStale
}

// wineHealth fills the Wine part of a health snapshot.
func wineHealth(state wineState, age time.Duration, beatRead bool) WineHealth {
	var health WineHealth
	if state == wineStateAbsent {
		return health
	}
	health.Present = true
	health.AbiVersion = wineABIVersion
	health.Stale = state == wineStateStale
	if beatRead {
		seconds := int64(age / time.Second)
		if age < 0 && age%time.Second != 0 {
			seconds--
		}
		health.HeartbeatAgeSeconds = &seconds
	}
	return health
}

// wineHealthOrigin gives noteWineHealth a monotonic clock, so a step of the
// wall clock doesn't stall the samples.
var wineHealthOrigin = time.Now()

// noteWineHealth samples the Wine publication state from the lookup path, at
// most once per wineHeartbeatLimit. The /process-lookup route samples on
// demand instead. Neither starts a goroutine, so a config reload leaves
// nothing running.
func noteWineHealth(dir string) {
	w := wineFlowMaps
	now := int64(time.Since(wineHealthOrigin)) + 1
	last := w.healthChecked.Load()
	if last != 0 && now-last < int64(wineHeartbeatLimit) {
		return
	}
	if !w.healthChecked.CompareAndSwap(last, now) {
		return
	}
	w.sampleHealth(dir)
}

// sampleHealth examines the Wine publication point the way a lookup does,
// records the state and logs a transition once. The heartbeat age is valid
// only when beatRead is true.
func (w *wineFlows) sampleHealth(dir string) (state wineState, age time.Duration, beatRead bool) {
	w.mu.Lock()
	if w.pinned.stale() {
		w.refreshLocked(dir)
	}
	open := w.flowsFd >= 0
	if open {
		age, beatRead = w.heartbeatAgeLocked()
	}
	w.mu.Unlock()
	state = winePublicationState(open, beatRead, age)
	if prev := wineState(w.healthState.Swap(int32(state))); prev != state {
		if message, warn := wineTransition(prev, state, dir); message != "" {
			if warn {
				log.Warnln("[Process] %s", message)
			} else {
				log.Infoln("[Process] %s", message)
			}
		}
	}
	return state, age, beatRead
}
