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

	hosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example", ""}
	var ips []netip.Addr
	for i := 1; i <= 6; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}))
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
	require.Empty(t, w.hosts)
	require.Empty(t, w.ips)
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

func TestFakeIpWriterWithoutDatabase(t *testing.T) {
	w := (&CacheFile{}).FakeIpWriter()
	ip := netip.MustParseAddr("198.18.0.4")
	w.PutByHost("x.example", ip)
	w.PutByIP(ip, "x.example")
	w.DelByIP(ip)
	w.Sync()
	_, ok := w.GetByHost("x.example")
	require.False(t, ok)
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
