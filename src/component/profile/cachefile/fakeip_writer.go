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
	hosts   map[string]pendingFakeIp
	ips     map[netip.Addr]pendingFakeHost
	queued  uint64 // sequence number of the last queued write
	done    uint64 // writes up to this number are committed or dropped
	running bool   // a commit goroutine is active
}

type fakeIpOpKind uint8

const (
	fakeIpPutHost fakeIpOpKind = iota
	fakeIpPutIP
	fakeIpDelIP
)

type fakeIpOp struct {
	kind fakeIpOpKind
	seq  uint64
	host string
	ip   netip.Addr
}

type pendingFakeIp struct {
	ip      netip.Addr
	deleted bool
	seq     uint64
}

type pendingFakeHost struct {
	host    string
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

func fakeIpWriterFor(store *FakeIpStore) *FakeIpWriter {
	key := fakeIpWriterKey{store.DB, string(store.bucketName)}
	fakeIpWriters.Lock()
	defer fakeIpWriters.Unlock()
	if w, ok := fakeIpWriters.m[key]; ok {
		return w
	}
	w := &FakeIpWriter{
		store: store,
		hosts: map[string]pendingFakeIp{},
		ips:   map[netip.Addr]pendingFakeHost{},
	}
	w.settled = sync.NewCond(&w.mu)
	fakeIpWriters.m[key] = w
	return w
}

func (w *FakeIpWriter) GetByHost(host string) (netip.Addr, bool) {
	w.mu.Lock()
	p, ok := w.hosts[host]
	w.mu.Unlock()
	if ok {
		return p.ip, !p.deleted
	}
	return w.store.GetByHost(host)
}

func (w *FakeIpWriter) GetByIP(ip netip.Addr) (string, bool) {
	w.mu.Lock()
	p, ok := w.ips[ip]
	w.mu.Unlock()
	if ok {
		return p.host, !p.deleted
	}
	return w.store.GetByIP(ip)
}

func (w *FakeIpWriter) PutByHost(host string, ip netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.DB == nil {
		return
	}
	if host == "" {
		// bbolt refuses empty keys; fail now, as FakeIpStore.PutByHost does,
		// rather than show the entry until its commit fails.
		log.Warnln("[CacheFile] write cache to %s failed: %s", w.store.DB.Path(), bbolt.ErrKeyRequired.Error())
		return
	}
	seq := w.nextLocked()
	w.hosts[host] = pendingFakeIp{ip: ip, seq: seq}
	w.queueLocked(fakeIpOp{kind: fakeIpPutHost, seq: seq, host: host, ip: ip})
}

func (w *FakeIpWriter) PutByIP(ip netip.Addr, host string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.DB == nil {
		return
	}
	seq := w.nextLocked()
	w.ips[ip] = pendingFakeHost{host: host, seq: seq}
	w.queueLocked(fakeIpOp{kind: fakeIpPutIP, seq: seq, host: host, ip: ip})
}

// DelByIP removes ip and the host key it names, like FakeIpStore.DelByIP.
func (w *FakeIpWriter) DelByIP(ip netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.DB == nil {
		return
	}
	// The committed transaction reads the host from the bucket after every
	// earlier write; the pending entries plus the database give the same view.
	host, ok := "", false
	if p, pending := w.ips[ip]; pending {
		host, ok = p.host, !p.deleted
	} else {
		host, ok = w.store.GetByIP(ip)
	}
	seq := w.nextLocked()
	w.ips[ip] = pendingFakeHost{deleted: true, seq: seq}
	if ok && host != "" {
		w.hosts[host] = pendingFakeIp{deleted: true, seq: seq}
	}
	w.queueLocked(fakeIpOp{kind: fakeIpDelIP, seq: seq, ip: ip})
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

// FlushFakeIP drops pending writes and deletes the bucket.
func (w *FakeIpWriter) FlushFakeIP() error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ops = nil
	w.hosts = map[string]pendingFakeIp{}
	w.ips = map[netip.Addr]pendingFakeHost{}
	w.done = w.queued
	w.settled.Broadcast()
	// Still holding mu: readers must not see old entries between dropping
	// the pending writes and deleting the bucket.
	return w.store.FlushFakeIP()
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
		for host, p := range w.hosts {
			if p.seq <= last {
				delete(w.hosts, host)
			}
		}
		for ip, p := range w.ips {
			if p.seq <= last {
				delete(w.ips, ip)
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

// applyFakeIpOps writes ops in order. A write bbolt rejects (an empty host
// key, for one) is logged and skipped without aborting the others, as
// FakeIpStore's separate batched writes would.
func applyFakeIpOps(t *bbolt.Tx, bucketName []byte, ops []fakeIpOp) error {
	bucket, err := t.CreateBucketIfNotExists(bucketName)
	if err != nil {
		return err
	}
	for _, op := range ops {
		switch op.kind {
		case fakeIpPutHost:
			err = bucket.Put([]byte(op.host), op.ip.AsSlice())
		case fakeIpPutIP:
			err = bucket.Put(op.ip.AsSlice(), []byte(op.host))
		case fakeIpDelIP:
			addr := op.ip.AsSlice()
			host := append([]byte(nil), bucket.Get(addr)...)
			err = bucket.Delete(addr)
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
