package applicationhostname

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type testCandidate struct{ valid atomic.Bool }

func (*testCandidate) Name() string { return "route.invalid" }
func (c *testCandidate) Validate() error {
	if !c.valid.Load() {
		return ErrUnavailable
	}
	return nil
}

type testReader struct {
	candidate Candidate
	closed    atomic.Int32
	deadline  time.Time
}

func (r *testReader) Lookup(_ Flow, deadline time.Time) (Candidate, error) {
	r.deadline = deadline
	return r.candidate, nil
}
func (r *testReader) Close() { r.closed.Add(1) }
func config() Config         { return Config{Enable: true, Endpoint: "/run/test/bootstrap.sock", WaitMS: 250} }
func flow() Flow {
	return Flow{Netns: 1, Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("192.0.2.2:443")}
}
func awaitClosed(t *testing.T, r *testReader) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for r.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.closed.Load() != 1 {
		t.Fatal("routing reader was not closed exactly once")
	}
}

func TestLookupReloadAndClose(t *testing.T) {
	for _, scenario := range []string{"reload", "disable", "close", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := &testCandidate{}
			candidate.valid.Store(true)
			r := &testReader{candidate: candidate}
			m := New(func(context.Context, string, time.Time) (Reader, error) { return r, nil })
			cfg := config()
			if scenario == "expired" {
				cfg.WaitMS = 10
			}
			if err := m.Configure(cfg); err != nil {
				t.Fatal(err)
			}
			e, err := m.Lookup(flow())
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if !e.Validate() || e.Name() != "route.invalid" {
				t.Fatal("live candidate rejected")
			}
			switch scenario {
			case "reload":
				m.Configure(cfg)
			case "disable":
				m.Configure(Config{})
			case "close":
				e.Close()
			case "expired":
				time.Sleep(15 * time.Millisecond)
			}
			if e.Validate() {
				t.Fatal("candidate survived its configuration/deadline")
			}
			awaitClosed(t, r)
			e.Close()
			if r.closed.Load() != 1 {
				t.Fatal("double close")
			}
		})
	}
}

func TestLookupAbsoluteBudgetAndCancellation(t *testing.T) {
	for _, at := range []string{"bootstrap", "poll"} {
		t.Run(at, func(t *testing.T) {
			started := make(chan struct{})
			reader := &testReader{}
			m := New(func(ctx context.Context, _ string, deadline time.Time) (Reader, error) {
				if d, ok := ctx.Deadline(); !ok || !d.Equal(deadline) {
					t.Error("bootstrap received a different deadline")
				}
				close(started)
				if at == "bootstrap" {
					<-ctx.Done()
					return reader, ctx.Err()
				}
				return reader, nil
			})
			m.Configure(config())
			done := make(chan error, 1)
			go func() {
				e, err := m.Lookup(flow())
				if e != nil {
					e.Close()
				}
				done <- err
			}()
			<-started
			m.Configure(Config{})
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("disabled lookup produced evidence")
				}
			case <-time.After(time.Second):
				t.Fatal("disable left a pending lookup")
			}
			awaitClosed(t, reader)
		})
	}
	reader := &testReader{}
	m := New(func(context.Context, string, time.Time) (Reader, error) { return reader, nil })
	cfg := config()
	cfg.WaitMS = 20
	m.Configure(cfg)
	start := time.Now()
	e, err := m.Lookup(flow())
	if e != nil || err == nil || time.Since(start) < 20*time.Millisecond || time.Since(start) > time.Second {
		t.Fatal("unknown result extended or skipped the absolute budget")
	}
	awaitClosed(t, reader)
}

func TestLookupCapacityAndFailure(t *testing.T) {
	var opens atomic.Int32
	candidate := &testCandidate{}
	candidate.valid.Store(true)
	m := New(func(context.Context, string, time.Time) (Reader, error) {
		opens.Add(1)
		return &testReader{candidate: candidate}, nil
	})
	m.Configure(config())
	var evidence []*Evidence
	defer func() {
		for _, e := range evidence {
			e.Close()
		}
	}()
	for i := 0; i < MaxPending; i++ {
		e, err := m.Lookup(flow())
		if err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, e)
	}
	if e, err := m.Lookup(flow()); e != nil || err == nil || opens.Load() != MaxPending {
		t.Fatal("capacity exhaustion opened another reader")
	}
	evidence[0].Close()
	e, err := m.Lookup(flow())
	if err != nil {
		t.Fatal("permit was not released")
	}
	e.Close()
	r := &testReader{}
	broken := New(func(context.Context, string, time.Time) (Reader, error) { return r, errors.New("failed after opening") })
	broken.Configure(config())
	if e, err := broken.Lookup(flow()); e != nil || err == nil {
		t.Fatal("open failure produced evidence")
	}
	awaitClosed(t, r)
}

func TestConfigurationValidationAndDisabledPath(t *testing.T) {
	m := New(nil)
	if err := m.Configure(Config{}); err != nil {
		t.Fatal(err)
	}
	if e, err := m.Lookup(flow()); e != nil || err == nil {
		t.Fatal("disabled path performed a lookup")
	}
	if m.Configure(config()) == nil {
		t.Fatal("normal build accepted unavailable backend")
	}
	m = New(func(context.Context, string, time.Time) (Reader, error) { panic("configuration dialed") })
	for _, cfg := range []Config{{Enable: true, Endpoint: "relative", WaitMS: 1}, {Enable: true, Endpoint: "/run/../test", WaitMS: 1}, {Enable: true, Endpoint: "/run/test", WaitMS: 0}, {WaitMS: 251}, {WaitMS: -1}} {
		if m.Configure(cfg) == nil {
			t.Fatalf("accepted invalid config %+v", cfg)
		}
	}
}
