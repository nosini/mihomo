package fakeip

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func newWriterTestPool(t *testing.T, db *bbolt.DB, ipnet netip.Prefix) *Pool {
	t.Helper()
	pool, err := New(Options{IPNet: ipnet, Size: 10})
	require.NoError(t, err)
	pool.store = newCachefileStore(&cachefile.CacheFile{DB: db}, ipnet)
	pool.restoreState()
	return pool
}

func openWriterTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600,
		&bbolt.Options{Timeout: time.Second, NoStatistics: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Lookups and LookBack must not wait for the cache file, and a pool created
// on a config reload must see the mappings its predecessor has not yet
// committed.
func TestPoolCachefileLookupDoesNotWaitForDisk(t *testing.T) {
	ipnet := netip.MustParsePrefix("198.18.0.0/24")
	db := openWriterTestDB(t)
	old := newWriterTestPool(t, db, ipnet)
	old.Lookup("earlier.example")
	// As at a previous shutdown; without a stored offset, restoreState flushes.
	old.StoreState()

	tx, err := db.Begin(true) // holds the database's write lock
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() }) // before the database closes
	type result struct {
		ip   netip.Addr
		host string
		ok   bool
	}
	done := make(chan result, 1)
	go func() {
		ip := old.Lookup("first.example")
		host, ok := old.LookBack(ip)
		done <- result{ip, host, ok}
	}()
	var first result
	select {
	case first = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Lookup waited for the cache file")
	}
	require.True(t, first.ok)
	require.Equal(t, "first.example", first.host)

	reloaded := newWriterTestPool(t, db, ipnet)
	reloaded.CloneFrom(old)
	require.Equal(t, first.ip, reloaded.Lookup("first.example"))
	second := reloaded.Lookup("second.example")
	require.NotEqual(t, first.ip, second)
	host, ok := reloaded.LookBack(second)
	require.True(t, ok)
	require.Equal(t, "second.example", host)

	require.NoError(t, tx.Rollback())
}

// StoreState runs at shutdown: the allocation state and every mapping before
// it must be in the cache file when it returns.
func TestPoolCachefileStoreStateCommits(t *testing.T) {
	ipnet := netip.MustParsePrefix("198.18.0.0/24")
	db := openWriterTestDB(t)
	pool := newWriterTestPool(t, db, ipnet)
	ip := pool.Lookup("kept.example")
	pool.Lookup("other.example")
	pool.StoreState()

	raw := (&cachefile.CacheFile{DB: db}).FakeIpStore()
	offset, ok := raw.GetByHost(offsetKey)
	require.True(t, ok)
	require.Equal(t, pool.offset, offset)
	got, ok := raw.GetByHost("kept.example")
	require.True(t, ok)
	require.Equal(t, ip, got)
	host, ok := raw.GetByIP(ip)
	require.True(t, ok)
	require.Equal(t, "kept.example", host)
}
