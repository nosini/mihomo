package statistic

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInfo(host, process string, up, down int64) *TrackerInfo {
	return &TrackerInfo{
		UUID: utils.NewUUIDV4(),
		Metadata: &C.Metadata{
			Host:    host,
			DstIP:   netip.MustParseAddr("192.0.2.1"),
			SrcIP:   netip.MustParseAddr("198.51.100.7"),
			Process: process,
		},
		UploadTotal:   atomic.NewInt64(up),
		DownloadTotal: atomic.NewInt64(down),
		Chain:         C.Chain{"node-a", "Proxy"},
		Rule:          "DomainSuffix",
		RulePayload:   "example.com",
	}
}

func newTestManager() *Manager {
	return &Manager{history: NewHistory()}
}

func TestHistoryRecordDimensions(t *testing.T) {
	h := NewHistory()
	h.Record(testInfo("a.example.com", "firefox", 10, 100))
	h.Record(testInfo("a.example.com", "curl", 1, 2))
	h.Record(testInfo("", "", 5, 5))

	s := h.State(nil)
	host := s.Top(DimensionHost, "total", 0)
	require.Len(t, host, 2)
	assert.Equal(t, "a.example.com", host[0].Name)
	assert.Equal(t, int64(11), host[0].Upload)
	assert.Equal(t, int64(102), host[0].Download)
	assert.Equal(t, int64(2), host[0].Connections)
	assert.Equal(t, "192.0.2.1", host[1].Name, "falls back to the destination IP")

	assert.Len(t, s.Top(DimensionProcess, "total", 0), 3)
	assert.Equal(t, "node-a", s.Top(DimensionProxy, "total", 0)[0].Name)
	assert.Equal(t, "DomainSuffix,example.com", s.Top(DimensionRule, "total", 0)[0].Name)
	assert.Equal(t, "198.51.100.7", s.Top(DimensionSource, "total", 0)[0].Name)
}

func TestHistoryTopSortAndLimit(t *testing.T) {
	h := NewHistory()
	h.Record(testInfo("big-down", "", 1, 1000))
	h.Record(testInfo("big-up", "", 500, 1))
	h.Record(testInfo("many", "", 1, 1))
	h.Record(testInfo("many", "", 1, 1))
	h.Record(testInfo("many", "", 1, 1))
	s := h.State(nil)

	assert.Equal(t, "big-down", s.Top(DimensionHost, "total", 1)[0].Name)
	assert.Equal(t, "big-up", s.Top(DimensionHost, "upload", 1)[0].Name)
	assert.Equal(t, "many", s.Top(DimensionHost, "connections", 1)[0].Name)
	assert.Len(t, s.Top(DimensionHost, "total", 2), 2)
}

func TestHistoryStateIncludesOpenWithoutChangingHistory(t *testing.T) {
	h := NewHistory()
	h.Record(testInfo("a", "", 1, 1))
	open := testInfo("a", "", 10, 10)

	withOpen := h.State([]*TrackerInfo{open})
	assert.Equal(t, int64(22), withOpen.Top(DimensionHost, "total", 0)[0].Total())
	assert.Equal(t, int64(2), h.State(nil).Top(DimensionHost, "total", 0)[0].Total())
}

func TestHistoryMergeRoundTrip(t *testing.T) {
	h := NewHistory()
	h.Record(testInfo("a", "p", 3, 4))
	data, err := json.Marshal(h.State(nil))
	require.NoError(t, err)

	restored := &HistoryState{}
	require.NoError(t, json.Unmarshal(data, restored))
	restored.Since = time.Now().Add(-time.Hour)

	h2 := NewHistory()
	h2.Record(testInfo("a", "p", 1, 1))
	h2.Merge(restored)
	s := h2.State(nil)
	e := s.Top(DimensionHost, "total", 0)[0]
	assert.Equal(t, int64(4), e.Upload)
	assert.Equal(t, int64(5), e.Download)
	assert.Equal(t, int64(2), e.Connections)
	assert.True(t, s.Since.Equal(restored.Since), "keeps the earlier start")

	h2.Merge(&HistoryState{Entries: map[string]map[string]*HistoryEntry{"unknown": {"x": {Name: "x"}}}})
	_, ok := h2.State(nil).Entries["unknown"]
	assert.False(t, ok)
}

func TestHistoryPruneKeepsLargest(t *testing.T) {
	h := NewHistory()
	for i := 0; i <= maxHistoryEntries; i++ {
		h.Record(testInfo(fmt.Sprintf("h%d", i), "", int64(i), 0))
	}
	s := h.State(nil)
	hosts := s.Entries[DimensionHost]
	assert.Len(t, hosts, maxHistoryEntries*9/10)
	assert.Contains(t, hosts, fmt.Sprintf("h%d", maxHistoryEntries))
	assert.NotContains(t, hosts, "h0")
}

func TestHistoryReset(t *testing.T) {
	h := NewHistory()
	h.Record(testInfo("a", "", 1, 1))
	h.Reset()
	assert.Empty(t, h.State(nil).Entries[DimensionHost])
}

func TestManagerLeaveRecordsOnce(t *testing.T) {
	m := newTestManager()
	tt := &tcpTracker{TrackerInfo: testInfo("a", "", 1, 1), manager: m, pushToManager: true}
	m.Join(tt)
	assert.Equal(t, int64(1), m.HistoryState().Entries[DimensionHost]["a"].Connections, "open connection is shown")

	m.Leave(tt)
	m.Leave(tt)
	assert.Equal(t, int64(1), m.history.State(nil).Entries[DimensionHost]["a"].Connections)
}

func TestManagerLeaveSkipsUncounted(t *testing.T) {
	m := newTestManager()
	ut := &udpTracker{TrackerInfo: testInfo("dns", "", 1, 1), manager: m, pushToManager: false}
	m.Join(ut)
	assert.Empty(t, m.HistoryState().Entries[DimensionHost])
	m.Leave(ut)
	assert.Empty(t, m.history.State(nil).Entries[DimensionHost])
}
