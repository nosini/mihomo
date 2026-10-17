package executor_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/applicationhostname"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
)

type candidate struct{}

func (candidate) Name() string    { return "route.invalid" }
func (candidate) Validate() error { return nil }

type reader struct{}

func (reader) Lookup(A.Flow, time.Time) (A.Candidate, error) { return candidate{}, nil }
func (reader) Close()                                        {}

func TestParsingDoesNotRevokeHostnameEvidence(t *testing.T) {
	previous := A.Default
	defer func() { A.Default.Configure(A.Config{}); A.Default = previous }()
	A.Default = A.New(func(context.Context, string, time.Time) (A.Reader, error) { return reader{}, nil })
	cfg := A.Config{Enable: true, Endpoint: "/run/test/bootstrap.sock", WaitMS: 250}
	if err := A.Default.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	e, err := A.Default.Lookup(A.Flow{Netns: 1, Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("192.0.2.2:443")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := config.ParseRawConfig(config.DefaultRawConfig()); err != nil {
		t.Fatal(err)
	}
	if executor.GetGeneral().HostnameDiscovery != cfg || !e.Validate() {
		t.Fatal("temporary config parsing changed hostname configuration or revoked pending evidence")
	}
}
