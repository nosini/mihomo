package statistic

import (
	"sync"
	"time"

	"golang.org/x/exp/slices"
)

// Dimensions that History groups closed connections by.
const (
	DimensionHost    = "host"
	DimensionProcess = "process"
	DimensionSource  = "source"
	DimensionProxy   = "proxy"
	DimensionRule    = "rule"
)

var Dimensions = []string{DimensionHost, DimensionProcess, DimensionSource, DimensionProxy, DimensionRule}

// maxHistoryEntries bounds each dimension; hosts seen only by IP would
// otherwise grow without limit.
const maxHistoryEntries = 10000

type HistoryEntry struct {
	Name        string    `json:"name"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Connections int64     `json:"connections"`
	LastSeen    time.Time `json:"lastSeen"`
}

func (e *HistoryEntry) Total() int64 {
	return e.Upload + e.Download
}

// HistoryState is the serialized form of History, used for persistence.
type HistoryState struct {
	Since   time.Time                           `json:"since"`
	Entries map[string]map[string]*HistoryEntry `json:"entries"`
}

// History accumulates traffic of closed connections per dimension.
type History struct {
	mu      sync.Mutex
	since   time.Time
	entries map[string]map[string]*HistoryEntry
}

func NewHistory() *History {
	h := &History{}
	h.Reset()
	return h
}

func (h *History) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.since = time.Now()
	h.entries = make(map[string]map[string]*HistoryEntry, len(Dimensions))
	for _, d := range Dimensions {
		h.entries[d] = make(map[string]*HistoryEntry)
	}
}

func historyKeys(info *TrackerInfo) map[string]string {
	m := info.Metadata
	host := m.Host
	if host == "" {
		host = m.SniffHost
	}
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	rule := info.Rule
	if info.RulePayload != "" {
		rule += "," + info.RulePayload
	}
	source := ""
	if m.SrcIP.IsValid() {
		source = m.SrcIP.String()
	}
	return map[string]string{
		DimensionHost:    host,
		DimensionProcess: m.Process,
		DimensionSource:  source,
		DimensionProxy:   info.Chain.Last(),
		DimensionRule:    rule,
	}
}

func addToDimension(entries map[string]*HistoryEntry, name string, up, down, conns int64, seen time.Time) {
	e, ok := entries[name]
	if !ok {
		e = &HistoryEntry{Name: name}
		entries[name] = e
	}
	e.Upload += up
	e.Download += down
	e.Connections += conns
	if seen.After(e.LastSeen) {
		e.LastSeen = seen
	}
}

// pruneDimension drops the smallest tenth of entries once a dimension
// grows past maxHistoryEntries, so pruning runs rarely.
func pruneDimension(entries map[string]*HistoryEntry) {
	if len(entries) <= maxHistoryEntries {
		return
	}
	list := make([]*HistoryEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	slices.SortFunc(list, func(a, b *HistoryEntry) int {
		return compareInt64(a.Total(), b.Total())
	})
	for _, e := range list[:len(list)-maxHistoryEntries*9/10] {
		delete(entries, e.Name)
	}
}

func compareInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// Record adds a closed connection.
func (h *History) Record(info *TrackerInfo) {
	keys := historyKeys(info)
	up, down := info.UploadTotal.Load(), info.DownloadTotal.Load()
	now := time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()
	for d, name := range keys {
		addToDimension(h.entries[d], name, up, down, 1, now)
		pruneDimension(h.entries[d])
	}
}

// State copies the accumulated totals, adding the current counts of the
// given open connections.
func (h *History) State(open []*TrackerInfo) *HistoryState {
	h.mu.Lock()
	state := &HistoryState{
		Since:   h.since,
		Entries: make(map[string]map[string]*HistoryEntry, len(h.entries)),
	}
	for d, entries := range h.entries {
		copied := make(map[string]*HistoryEntry, len(entries))
		for name, e := range entries {
			c := *e
			copied[name] = &c
		}
		state.Entries[d] = copied
	}
	h.mu.Unlock()

	now := time.Now()
	for _, info := range open {
		up, down := info.UploadTotal.Load(), info.DownloadTotal.Load()
		for d, name := range historyKeys(info) {
			addToDimension(state.Entries[d], name, up, down, 1, now)
		}
	}
	return state
}

// Merge adds previously saved totals, keeping the earlier start time.
func (h *History) Merge(state *HistoryState) {
	if state == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !state.Since.IsZero() && state.Since.Before(h.since) {
		h.since = state.Since
	}
	for d, entries := range state.Entries {
		target, ok := h.entries[d]
		if !ok {
			continue
		}
		for name, e := range entries {
			if e == nil {
				continue
			}
			addToDimension(target, name, e.Upload, e.Download, e.Connections, e.LastSeen)
		}
		pruneDimension(target)
	}
}

// Top returns the largest entries of one dimension, ordered by sortBy
// ("total", "upload", "download" or "connections"). limit <= 0 returns all.
func (s *HistoryState) Top(dimension, sortBy string, limit int) []*HistoryEntry {
	entries := s.Entries[dimension]
	list := make([]*HistoryEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	value := func(e *HistoryEntry) int64 {
		switch sortBy {
		case "upload":
			return e.Upload
		case "download":
			return e.Download
		case "connections":
			return e.Connections
		default:
			return e.Total()
		}
	}
	slices.SortFunc(list, func(a, b *HistoryEntry) int {
		if c := compareInt64(value(b), value(a)); c != 0 {
			return c
		}
		if a.Name < b.Name {
			return -1
		} else if a.Name > b.Name {
			return 1
		}
		return 0
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}
