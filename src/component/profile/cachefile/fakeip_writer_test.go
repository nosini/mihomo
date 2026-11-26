package cachefile

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func openTestCache(t *testing.T) *CacheFile {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600,
		&bbolt.Options{Timeout: time.Second})
	require.NoError(t, err)
	db.NoSync = true
	t.Cleanup(func() { _ = db.Close() })
	return &CacheFile{DB: db}
}

func bucketContents(t *testing.T, db *bbolt.DB, name []byte) map[string]string {
	t.Helper()
	m := map[string]string{}
	require.NoError(t, db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(name)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			m[string(k)] = string(v)
			return nil
		})
	}))
	return m
}

// The writer must give the same reads and leave the same bucket as the
// synchronous FakeIpStore for any sequence of writes, committed or pending.
func TestFakeIpWriterMatchesStore(t *testing.T) {
	ref := openTestCache(t)
	ref.DB.MaxBatchDelay = 0 // plain Update per write; only speeds up the test
	want := ref.FakeIpStore()
	got := openTestCache(t).FakeIpWriter()

	// Host names and raw IP bytes share the bucket's key space: "docs" and
	// "data" are also the keys of 100.111.99.115 and 100.97.116.97. The
	// invalid address has an empty key, which bbolt refuses.
	hosts := []string{"a.example", "b.example", "c.example", "docs", "data", ""}
	ips := []netip.Addr{
		netip.MustParseAddr("100.111.99.115"),
		netip.MustParseAddr("100.97.116.97"),
		netip.MustParseAddr("100.64.0.4"),
		netip.MustParseAddr("100.64.0.5"),
		netip.MustParseAddr("100.64.0.6"),
		{},
	}
	rng := rand.New(rand.NewSource(1))
	for step := 0; step < 1500; step++ {
		host, ip := hosts[rng.Intn(len(hosts))], ips[rng.Intn(len(ips))]
		var desc string
		switch rng.Intn(7) {
		case 0, 1:
			desc = fmt.Sprintf("PutByHost(%q, %s)", host, ip)
			want.PutByHost(host, ip)
			got.PutByHost(host, ip)
		case 2, 3:
			desc = fmt.Sprintf("PutByIP(%s, %q)", ip, host)
			want.PutByIP(ip, host)
			got.PutByIP(ip, host)
		case 4, 5:
			desc = fmt.Sprintf("DelByIP(%s)", ip)
			want.DelByIP(ip)
			got.DelByIP(ip)
		case 6:
			desc = "Sync"
			got.Sync()
		}
		for _, h := range hosts {
			wantIP, wantOK := want.GetByHost(h)
			gotIP, gotOK := got.GetByHost(h)
			require.Equal(t, wantOK, gotOK, "step %d %s: GetByHost(%q)", step, desc, h)
			if wantOK {
				require.Equal(t, wantIP, gotIP, "step %d %s: GetByHost(%q)", step, desc, h)
			}
		}
		for _, a := range ips {
			wantHost, wantOK := want.GetByIP(a)
			gotHost, gotOK := got.GetByIP(a)
			require.Equal(t, wantOK, gotOK, "step %d %s: GetByIP(%s)", step, desc, a)
			require.Equal(t, wantHost, gotHost, "step %d %s: GetByIP(%s)", step, desc, a)
		}
	}
	got.Sync()
	require.Equal(t, bucketContents(t, ref.DB, bucketFakeip),
		bucketContents(t, got.store.DB, bucketFakeip))
}

// Writes return while the database is busy, reads see them at once, and they
// reach the database once it is free again.
func TestFakeIpWriterDoesNotWaitForCommit(t *testing.T) {
	cache := openTestCache(t)
	w := cache.FakeIpWriter()
	raw := cache.FakeIpStore()
	host, ip := "pending.example", netip.MustParseAddr("198.18.0.9")

	tx, err := cache.DB.Begin(true) // holds the database's write lock
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() }) // before the database closes
	wrote := make(chan struct{})
	go func() {
		w.PutByIP(ip, host)
		w.PutByHost(host, ip)
		close(wrote)
	}()
	select {
	case <-wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("writes waited for the database")
	}
	gotIP, ok := w.GetByHost(host)
	require.True(t, ok)
	require.Equal(t, ip, gotIP)
	gotHost, ok := w.GetByIP(ip)
	require.True(t, ok)
	require.Equal(t, host, gotHost)
	_, ok = raw.GetByHost(host)
	require.False(t, ok, "committed while the database was locked")

	require.NoError(t, tx.Rollback())
	w.Sync()
	gotIP, ok = raw.GetByHost(host)
	require.True(t, ok)
	require.Equal(t, ip, gotIP)
	gotHost, ok = raw.GetByIP(ip)
	require.True(t, ok)
	require.Equal(t, host, gotHost)
	w.mu.Lock()
	defer w.mu.Unlock()
	require.Empty(t, w.pending)
}

func TestFakeIpWriterFlush(t *testing.T) {
	cache := openTestCache(t)
	w := cache.FakeIpWriter()
	raw := cache.FakeIpStore()
	a, b := netip.MustParseAddr("198.18.0.4"), netip.MustParseAddr("198.18.0.5")
	w.PutByHost("old.example", a)
	w.PutByIP(a, "old.example")
	w.Sync()
	w.PutByHost("pending.example", b)

	require.NoError(t, w.FlushFakeIP())
	w.Sync() // must not wait for dropped writes
	for _, h := range []string{"old.example", "pending.example"} {
		_, ok := w.GetByHost(h)
		require.False(t, ok, h)
		_, ok = raw.GetByHost(h)
		require.False(t, ok, h)
	}
	_, ok := w.GetByIP(a)
	require.False(t, ok)

	w.PutByHost("new.example", b)
	w.Sync()
	got, ok := raw.GetByHost("new.example")
	require.True(t, ok)
	require.Equal(t, b, got)
	require.Len(t, bucketContents(t, cache.DB, bucketFakeip), 1)
}

func TestFakeIpWriterSharedPerBucket(t *testing.T) {
	cache := openTestCache(t)
	require.Same(t, cache.FakeIpWriter(), cache.FakeIpWriter())
	require.Same(t, cache.FakeIpWriter(), (&CacheFile{DB: cache.DB}).FakeIpWriter())
	require.NotSame(t, cache.FakeIpWriter(), cache.FakeIpWriter6())
	require.NotSame(t, cache.FakeIpWriter(), openTestCache(t).FakeIpWriter())
}

// Without a cache file every write is dropped, as with FakeIpStore, and a
// flush has nothing to delete.
func TestFakeIpWriterWithoutDatabase(t *testing.T) {
	w := (&CacheFile{}).FakeIpWriter()
	ip := netip.MustParseAddr("198.18.0.4")
	w.PutByHost("x.example", ip)
	w.PutByIP(ip, "x.example")
	_, ok := w.GetByHost("x.example")
	require.False(t, ok)
	_, ok = w.GetByIP(ip)
	require.False(t, ok)
	w.DelByIP(ip)
	w.Sync()
	require.NoError(t, w.FlushFakeIP())
}

// A failed commit is logged and its writes dropped, as FakeIpStore drops a
// failed write; Sync must not wait for them.
func TestFakeIpWriterCommitFailure(t *testing.T) {
	db := openReadOnlyTestDB(t)

	w := (&CacheFile{DB: db}).FakeIpWriter()
	w.PutByHost("lost.example", netip.MustParseAddr("198.18.0.5"))
	w.DelByIP(netip.MustParseAddr("198.18.0.4"))
	w.Sync()
	_, ok := w.GetByHost("lost.example")
	require.False(t, ok)
	got, ok := w.GetByHost("kept.example")
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("198.18.0.4"), got)
	require.Error(t, w.FlushFakeIP())
	got, ok = w.GetByHost("kept.example")
	require.True(t, ok, "a failed flush must leave the entries")
	require.Equal(t, netip.MustParseAddr("198.18.0.4"), got)
}

// A failed flush keeps pending writes queued rather than dropping them.
func TestFakeIpWriterFailedFlushKeepsPendingWrites(t *testing.T) {
	w := (&CacheFile{DB: openReadOnlyTestDB(t)}).FakeIpWriter()
	ip := netip.MustParseAddr("198.18.0.5")
	// Marked as running, the writer starts no commit goroutine, so the write
	// is still pending when the flush runs.
	w.mu.Lock()
	w.running = true
	w.mu.Unlock()
	w.PutByHost("pending.example", ip)

	require.Error(t, w.FlushFakeIP())
	got, ok := w.GetByHost("pending.example")
	require.True(t, ok, "the failed flush dropped a pending write")
	require.Equal(t, ip, got)
	w.mu.Lock()
	require.Len(t, w.ops, 1)
	w.mu.Unlock()

	w.commitLoop() // read-only: the commit fails and drops the write
	w.Sync()
	_, ok = w.GetByHost("pending.example")
	require.False(t, ok)
}

// openReadOnlyTestDB returns a read-only database whose fake-IP bucket maps
// kept.example to 198.18.0.4; every write transaction on it fails.
func openReadOnlyTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache.db")
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		return b.Put([]byte("kept.example"), []byte{198, 18, 0, 4})
	}))
	require.NoError(t, db.Close())
	db, err = bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second, ReadOnly: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Shutdown waits for every writer, including those of pools a reload
// dropped.
func TestSyncFakeIpWriters(t *testing.T) {
	caches := []*CacheFile{openTestCache(t), openTestCache(t)}
	var txs []*bbolt.Tx
	for i, cache := range caches {
		tx, err := cache.DB.Begin(true)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		txs = append(txs, tx)
		cache.FakeIpWriter().PutByHost(fmt.Sprintf("w%d.example", i), netip.MustParseAddr("198.18.0.4"))
		cache.FakeIpWriter6().PutByHost(fmt.Sprintf("w%d.example", i), netip.MustParseAddr("fdfe:dcba::4"))
	}
	synced := make(chan struct{})
	go func() {
		SyncFakeIpWriters()
		close(synced)
	}()
	select {
	case <-synced:
		t.Fatal("returned before the writes were committed")
	case <-time.After(100 * time.Millisecond):
	}
	for _, tx := range txs {
		require.NoError(t, tx.Rollback())
	}
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("did not return after the commits")
	}
	for i, cache := range caches {
		_, ok := cache.FakeIpStore().GetByHost(fmt.Sprintf("w%d.example", i))
		require.True(t, ok)
		_, ok = cache.FakeIpStore6().GetByHost(fmt.Sprintf("w%d.example", i))
		require.True(t, ok)
	}
}

// Overlapping writes, deletes, flushes and syncs from many goroutines; run
// with -race. Afterwards the writer must read exactly what the bucket holds.
func TestFakeIpWriterConcurrentMixed(t *testing.T) {
	cache := openTestCache(t)
	w := cache.FakeIpWriter()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 300; i++ {
				host := fmt.Sprintf("h%d.example", rng.Intn(16))
				ip := netip.AddrFrom4([4]byte{198, 18, 0, byte(rng.Intn(16))})
				switch rng.Intn(20) {
				case 0:
					_ = w.FlushFakeIP()
				case 1:
					w.Sync()
				case 2, 3, 4:
					w.DelByIP(ip)
				case 5, 6, 7, 8:
					w.GetByHost(host)
					w.GetByIP(ip)
				default:
					w.PutByIP(ip, host)
					w.PutByHost(host, ip)
				}
			}
		}(g)
	}
	wg.Wait()
	w.Sync()
	contents := bucketContents(t, cache.DB, bucketFakeip)
	for i := 0; i < 16; i++ {
		host := fmt.Sprintf("h%d.example", i)
		ip, ok := w.GetByHost(host)
		v, inDB := contents[host]
		require.Equal(t, inDB, ok, host)
		if ok {
			require.Equal(t, v, string(ip.AsSlice()), host)
		}
		a := netip.AddrFrom4([4]byte{198, 18, 0, byte(i)})
		h, ok := w.GetByIP(a)
		v, inDB = contents[string(a.AsSlice())]
		require.Equal(t, inDB, ok, a.String())
		require.Equal(t, v, h, a.String())
	}
}

func TestFakeIpWriterConcurrent(t *testing.T) {
	cache := openTestCache(t)
	w := cache.FakeIpWriter6()
	const workers, each = 8, 150
	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				host := fmt.Sprintf("w%d-%d.example", g, i)
				var a [16]byte
				a[0], a[1], a[14], a[15] = 0xfd, 0xfe, byte(g), byte(i)
				ip := netip.AddrFrom16(a)
				w.PutByIP(ip, host)
				w.PutByHost(host, ip)
				got, ok := w.GetByHost(host)
				if !ok || got != ip {
					t.Errorf("GetByHost(%s) = %s, %v", host, got, ok)
				}
			}
		}(g)
	}
	wg.Wait()
	w.Sync()
	contents := bucketContents(t, cache.DB, bucketFakeip6)
	require.Len(t, contents, 2*workers*each)
	for k, v := range contents {
		if bytes.HasSuffix([]byte(k), []byte(".example")) {
			require.Len(t, v, 16, k)
		}
	}
}
