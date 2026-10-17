// Package applicationhostname manages optional, bounded application-name reads.
// The normal build has no backend; the optional adapter requires an explicit
// build tag and the separately versioned hostname reader module.
package applicationhostname

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MaxWaitMS = 250
const MaxPending = 64

type Config struct {
	Enable   bool   `yaml:"enable" json:"enable"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	WaitMS   int    `yaml:"wait-ms" json:"wait-ms"`
}

type Flow struct {
	Netns               uint64
	Source, Destination netip.AddrPort
}
type Candidate interface {
	Name() string
	Validate() error
}
type Reader interface {
	Lookup(Flow, time.Time) (Candidate, error)
	Close()
}
type DialFunc func(context.Context, string, time.Time) (Reader, error)

var ErrUnavailable = errors.New("application hostname unavailable")

// ErrNoFlow from a Reader means the observer has no record of the flow, so
// waiting cannot produce a name for this connection.
var ErrNoFlow = errors.New("application hostname flow was not observed")

type setting struct {
	config Config
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	active map[*Evidence]struct{}
}
type Manager struct {
	dial    DialFunc // immutable after construction
	current atomic.Pointer[setting]
	slots   chan struct{}
}

var Default = New(nil)

func New(dial DialFunc) *Manager { return &Manager{dial: dial, slots: make(chan struct{}, MaxPending)} }

func (m *Manager) Validate(config Config) error {
	if config.WaitMS < 0 || config.WaitMS > MaxWaitMS {
		return errors.New("hostname-discovery wait-ms must be between 0 and 250")
	}
	if !config.Enable {
		return nil
	}
	if config.WaitMS == 0 {
		return errors.New("enabled hostname-discovery requires an explicit wait-ms between 1 and 250")
	}
	if !filepath.IsAbs(config.Endpoint) || filepath.Clean(config.Endpoint) != config.Endpoint || len(config.Endpoint) >= 108 || strings.ContainsRune(config.Endpoint, 0) {
		return errors.New("hostname-discovery endpoint must be a canonical absolute Unix pathname")
	}
	if m.dial == nil {
		return errors.New("this build has no hostname-discovery backend; the optional backend requires hostname_discovery on Linux amd64")
	}
	return nil
}

// Configure invalidates all uncommitted evidence, including on an otherwise
// identical reload. It does not alter already committed connections.
func (m *Manager) Configure(config Config) error {
	if err := m.Validate(config); err != nil {
		return err
	}
	var next *setting
	if config.Enable {
		ctx, cancel := context.WithCancel(context.Background())
		next = &setting{config: config, ctx: ctx, cancel: cancel, active: make(map[*Evidence]struct{})}
	}
	if old := m.current.Swap(next); old != nil {
		old.cancel()
		old.mu.Lock()
		pending := make([]*Evidence, 0, len(old.active))
		for evidence := range old.active {
			pending = append(pending, evidence)
		}
		old.mu.Unlock()
		for _, evidence := range pending {
			evidence.Close()
		}
	}
	return nil
}

func (m *Manager) Config() Config {
	if s := m.current.Load(); s != nil {
		return s.config
	}
	return Config{}
}

type Evidence struct {
	mu        sync.RWMutex
	state     *setting
	owner     *Manager
	deadline  time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	reader    Reader
	candidate Candidate
	release   func()
	timer     *time.Timer
	closed    bool
}

func (e *Evidence) Name() string { return e.candidate.Name() }

func (e *Evidence) Validate() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	live := func() bool {
		return !e.closed && e.owner.current.Load() == e.state && e.ctx.Err() == nil && time.Now().Before(e.deadline)
	}
	return live() && e.candidate.Validate() == nil && live()
}

func (e *Evidence) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	if e.timer != nil {
		e.timer.Stop()
	}
	e.cancel()
	e.state.mu.Lock()
	delete(e.state.active, e)
	e.state.mu.Unlock()
	e.reader.Close()
	e.release()
}

// Lookup opens at most one authenticated reader for this routing attempt. All
// bootstrap I/O, polls and final validation share the same absolute deadline.
// Capacity exhaustion and open failure return unknown immediately. No reader
// or positive result is cached or adopted from a replacement observer.
func (m *Manager) Lookup(flow Flow) (*Evidence, error) {
	s := m.current.Load()
	if s == nil || flow.Netns == 0 || !flow.Source.IsValid() || !flow.Destination.IsValid() || flow.Source.Port() == 0 || flow.Destination.Port() == 0 {
		return nil, ErrUnavailable
	}
	deadline := time.Now().Add(time.Duration(s.config.WaitMS) * time.Millisecond)
	select {
	case m.slots <- struct{}{}:
	default:
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(s.ctx, deadline)
	reader, err := m.dial(ctx, s.config.Endpoint, deadline)
	var evidence *Evidence
	defer func() {
		if evidence == nil {
			cancel()
			if reader != nil {
				reader.Close()
			}
			<-m.slots
		}
	}()
	if err != nil || ctx.Err() != nil || s.ctx.Err() != nil || reader == nil || !time.Now().Before(deadline) {
		return nil, ErrUnavailable
	}
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil || s.ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, ErrUnavailable
		}
		candidate, err := reader.Lookup(flow, deadline)
		// Connections from other processes never get a record; don't hold a
		// reader slot and delay their routing for the whole wait budget.
		if errors.Is(err, ErrNoFlow) {
			return nil, ErrUnavailable
		}
		if err == nil && candidate != nil && candidate.Name() != "" && ctx.Err() == nil && s.ctx.Err() == nil && time.Now().Before(deadline) {
			s.mu.Lock()
			if m.current.Load() != s || ctx.Err() != nil || !time.Now().Before(deadline) {
				s.mu.Unlock()
				return nil, ErrUnavailable
			}
			evidence = &Evidence{state: s, owner: m, deadline: deadline, ctx: ctx, cancel: cancel, reader: reader, candidate: candidate, release: func() { <-m.slots }}
			// Initialize under the evidence lock before publishing it to reload
			// or expiry cleanup. Close never holds the setting lock while waiting.
			evidence.mu.Lock()
			s.active[evidence] = struct{}{}
			evidence.timer = time.AfterFunc(time.Until(deadline), evidence.Close)
			s.mu.Unlock()
			evidence.mu.Unlock()
			return evidence, nil
		}
		select {
		case <-ctx.Done():
			return nil, ErrUnavailable
		case <-tick.C:
		}
	}
}
