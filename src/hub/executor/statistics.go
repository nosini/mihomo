package executor

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const statisticsSaveInterval = 5 * time.Minute

var statisticsState struct {
	sync.Mutex
	loaded   bool
	started  bool
	shutdown bool
}

// updateStatistics loads saved statistics the first time storing is
// enabled and starts the periodic save.
func updateStatistics(enabled bool) {
	profile.StoreStatistics.Store(enabled)
	if !enabled {
		return
	}

	statisticsState.Lock()
	defer statisticsState.Unlock()
	if !statisticsState.loaded {
		statisticsState.loaded = true
		if data := cachefile.Cache().GetStatistics(); data != nil {
			state := &statistic.HistoryState{}
			if err := json.Unmarshal(data, state); err != nil {
				log.Warnln("[Statistics] ignore saved statistics: %s", err.Error())
			} else {
				statistic.DefaultManager.History().Merge(state)
			}
		}
	}
	if !statisticsState.started {
		statisticsState.started = true
		go func() {
			for range time.Tick(statisticsSaveInterval) {
				saveStatistics(false)
			}
		}()
	}
}

// SaveStatistics writes the statistics to the cache file now, without the
// connections that are still open.
func SaveStatistics() {
	saveStatistics(false)
}

// saveStatistics writes the statistics if storing is enabled. Open
// connections are only included at shutdown, since later saves would count
// them again once they close.
func saveStatistics(final bool) {
	if !profile.StoreStatistics.Load() {
		return
	}
	statisticsState.Lock()
	defer statisticsState.Unlock()
	if statisticsState.shutdown {
		return
	}
	var state *statistic.HistoryState
	if final {
		statisticsState.shutdown = true
		state = statistic.DefaultManager.HistoryState()
	} else {
		state = statistic.DefaultManager.History().State(nil)
	}
	data, err := json.Marshal(state)
	if err != nil {
		log.Warnln("[Statistics] encode failed: %s", err.Error())
		return
	}
	cachefile.Cache().SetStatistics(data)
}
