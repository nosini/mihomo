package cachefile

import (
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

// FakeIpWriter is a FakeIpStore whose writes return at once. Pending writes
// stay in memory, where reads see them, until a background goroutine commits
// them in order, as many as are queued per transaction. Fake-IP lookups hold
// the pool lock, so waiting for the disk there would stall every new hostname
// and every connection to a fake IP behind each commit.
//
// Pending entries are keyed like the bucket: host names and raw IP bytes
// share one key space, so reads give what the committed bucket will hold.
//
// There is one writer per database and bucket. Pools built on a config reload
// share it with the pool they replace and see its pending writes.
type FakeIpWriter struct {
	store *FakeIpStore

	// writeMu serializes database transactions with FlushFakeIP. Lock order:
	// writeMu, then mu.
	writeMu sync.Mutex

	mu      sync.Mutex
	settled *sync.Cond
	ops     []fakeIpOp
	pending map[string]pendingFakeIpKey
	queued  uint64 // sequence number of the last queued write
	done    uint64 // writes up to this number are committed or dropped
	running bool   // a commit goroutine is active
}

type fakeIpOpKind uint8

const (
	fakeIpPut fakeIpOpKind = iota
	fakeIpDelIP
)

type fakeIpOp struct {
	kind  fakeIpOpKind
	seq   uint64
	key   []byte
	value []byte
}

type pendingFakeIpKey struct {
	value   []byte
	deleted bool
	seq     uint64
}

type fakeIpWriterKey struct {
	db     *bbolt.DB
	bucket string
}

var fakeIpWriters = struct {
	sync.Mutex
	m map[fakeIpWriterKey]*FakeIpWriter
}{m: map[fakeIpWriterKey]*FakeIpWriter{}}

// FakeIpWriter returns the shared writer for the IPv4 fake-IP bucket.
func (c *CacheFile) FakeIpWriter() *FakeIpWriter {
	return fakeIpWriterFor(c.FakeIpStore())
}

// FakeIpWriter6 returns the shared writer for the IPv6 fake-IP bucket.
func (c *CacheFile) FakeIpWriter6() *FakeIpWriter {
	return fakeIpWriterFor(c.FakeIpStore6())
}

// SyncFakeIpWriters waits until every writer has committed the writes queued
// before the call, including writers of pools a config reload has dropped.
func SyncFakeIpWriters() {
	fakeIpWriters.Lock()
	writers := make([]*FakeIpWriter, 0, len(fakeIpWriters.m))
	for _, w := range fakeIpWriters.m {
		writers = append(writers, w)
	}
	fakeIpWriters.Unlock()
	for _, w := range writers {
		w.Sync()
	}
}

func fakeIpWriterFor(store *FakeIpStore) *FakeIpWriter {
	key := fakeIpWriterKey{store.DB, string(store.bucketName)}
	fakeIpWriters.Lock()
	defer fakeIpWriters.Unlock()
	if w, ok := fakeIpWriters.m[key]; ok {
		return w
	}
	w := &FakeIpWriter{store: store, pending: map[string]pendingFakeIpKey{}}
	w.settled = sync.NewCond(&w.mu)
	fakeIpWriters.m[key] = w
	return w
}

// lookup returns the value of key as the committed bucket will hold it.
func (w *FakeIpWriter) lookup(key []byte) (value []byte, ok bool) {
	w.mu.Lock()
	p, pending := w.pending[string(key)]
	w.mu.Unlock()
	if pending {
		return p.value, !p.deleted
	}
	if w.store.DB == nil {
		return nil, false
	}
	_ = w.store.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(w.store.bucketName); bucket != nil {
			if v := bucket.Get(key); v != nil {
				value, ok = append([]byte{}, v...), true
			}
		}
		return nil
	})
	return value, ok
}

func (w *FakeIpWriter) GetByHost(host string) (netip.Addr, bool) {
	if v, ok := w.lookup([]byte(host)); ok {
		return netip.AddrFromSlice(v)
	}
	return netip.Addr{}, false
}

func (w *FakeIpWriter) GetByIP(ip netip.Addr) (string, bool) {
	if v, ok := w.lookup(ip.AsSlice()); ok {
		return string(v), true
	}
	return "", false
}

func (w *FakeIpWriter) PutByHost(host string, ip netip.Addr) {
	w.put([]byte(host), ip.AsSlice())
}

func (w *FakeIpWriter) PutByIP(ip netip.Addr, host string) {
	w.put(ip.AsSlice(), []byte(host))
}

func (w *FakeIpWriter) put(key, value []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.DB == nil {
		return
	}
	if len(key) == 0 {
		// bbolt refuses empty keys; fail now, as FakeIpStore does, rather
		// than show the entry until its commit fails.
		log.Warnln("[CacheFile] write cache to %s failed: %s", w.store.DB.Path(), bbolt.ErrKeyRequired.Error())
		return
	}
	value = append([]byte{}, value...)
	seq := w.nextLocked()
	w.pending[string(key)] = pendingFakeIpKey{value: value, seq: seq}
	w.queueLocked(fakeIpOp{kind: fakeIpPut, seq: seq, key: key, value: value})
}

// DelByIP removes ip and the key its value names, like FakeIpStore.DelByIP.
func (w *FakeIpWriter) DelByIP(ip netip.Addr) {
	key := ip.AsSlice()
	if w.store.DB == nil || len(key) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// The committed transaction reads the value from the bucket after every
	// earlier write; the pending entries plus the database give the same view.
	var host []byte
	if p, pending := w.pending[string(key)]; pending {
		if !p.deleted {
			host = p.value
		}
	} else {
		_ = w.store.DB.View(func(t *bbolt.Tx) error {
			if bucket := t.Bucket(w.store.bucketName); bucket != nil {
				host = append([]byte{}, bucket.Get(key)...)
			}
			return nil
		})
	}
	seq := w.nextLocked()
	w.pending[string(key)] = pendingFakeIpKey{deleted: true, seq: seq}
	if len(host) > 0 {
		w.pending[string(host)] = pendingFakeIpKey{deleted: true, seq: seq}
	}
	w.queueLocked(fakeIpOp{kind: fakeIpDelIP, seq: seq, key: key})
}

// Sync waits until every write queued before the call is committed.
func (w *FakeIpWriter) Sync() {
	w.mu.Lock()
	defer w.mu.Unlock()
	target := w.queued
	for w.done < target {
		w.settled.Wait()
	}
}

// FlushFakeIP deletes the bucket, then drops pending writes. If the delete
// fails, the pending writes stay queued.
func (w *FakeIpWriter) FlushFakeIP() error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.DB == nil {
		return nil
	}
	// Still holding mu: readers must not see old entries between deleting
	// the bucket and dropping the pending writes.
	if err := w.store.DB.Update(func(t *bbolt.Tx) error {
		if t.Bucket(w.store.bucketName) == nil {
			return nil
		}
		return t.DeleteBucket(w.store.bucketName)
	}); err != nil {
		return err
	}
	w.ops = nil
	w.pending = map[string]pendingFakeIpKey{}
	w.done = w.queued
	w.settled.Broadcast()
	return nil
}

func (w *FakeIpWriter) nextLocked() uint64 {
	w.queued++
	return w.queued
}

func (w *FakeIpWriter) queueLocked(op fakeIpOp) {
	w.ops = append(w.ops, op)
	if !w.running {
		w.running = true
		go w.commitLoop()
	}
}

func (w *FakeIpWriter) commitLoop() {
	for {
		w.writeMu.Lock()
		w.mu.Lock()
		ops := w.ops
		w.ops = nil
		if len(ops) == 0 {
			w.running = false
			w.mu.Unlock()
			w.writeMu.Unlock()
			return
		}
		w.mu.Unlock()

		if err := w.store.DB.Update(func(t *bbolt.Tx) error {
			return applyFakeIpOps(t, w.store.bucketName, ops)
		}); err != nil {
			log.Warnln("[CacheFile] write cache to %s failed: %s", w.store.DB.Path(), err.Error())
		}

		w.mu.Lock()
		last := ops[len(ops)-1].seq
		if last == w.queued {
			// Nothing newer is pending; a fresh map also gives back the
			// memory a burst made the old one grow to.
			w.pending = map[string]pendingFakeIpKey{}
		} else {
			for key, p := range w.pending {
				if p.seq <= last {
					delete(w.pending, key)
				}
			}
		}
		if last > w.done {
			w.done = last
		}
		w.settled.Broadcast()
		w.mu.Unlock()
		w.writeMu.Unlock()
	}
}

// applyFakeIpOps writes ops in order. A write bbolt rejects is logged and
// skipped without aborting the others, as FakeIpStore's separate batched
// writes would.
func applyFakeIpOps(t *bbolt.Tx, bucketName []byte, ops []fakeIpOp) error {
	bucket, err := t.CreateBucketIfNotExists(bucketName)
	if err != nil {
		return err
	}
	for _, op := range ops {
		switch op.kind {
		case fakeIpPut:
			err = bucket.Put(op.key, op.value)
		case fakeIpDelIP:
			host := append([]byte{}, bucket.Get(op.key)...)
			err = bucket.Delete(op.key)
			if err == nil && len(host) > 0 {
				err = bucket.Delete(host)
			}
		}
		if err != nil {
			log.Warnln("[CacheFile] write fake-ip cache entry failed: %s", err.Error())
		}
	}
	return nil
}
