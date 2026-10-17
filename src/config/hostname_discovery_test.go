package config

import (
	"context"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/applicationhostname"
)

func TestHostnameDiscoveryConfiguration(t *testing.T) {
	previous := A.Default
	defer func() { A.Default = previous }()
	A.Default = A.New(func(context.Context, string, time.Time) (A.Reader, error) {
		t.Fatal("parsing dialed the observer")
		return nil, A.ErrUnavailable
	})
	for _, mode := range []string{"off", "always"} {
		raw, err := UnmarshalRawConfig([]byte("find-process-mode: " + mode + "\nhostname-discovery:\n  enable: true\n  endpoint: /run/test/bootstrap.sock\n  wait-ms: 50\n"))
		if err != nil {
			t.Fatal(err)
		}
		general, err := parseGeneral(raw)
		if err != nil || !general.HostnameDiscovery.Enable || general.HostnameDiscovery.WaitMS != 50 || general.FindProcessMode.String() != mode {
			t.Fatalf("independent hostname configuration lost: %+v: %v", general, err)
		}
	}
	for _, text := range []string{"hostname-discovery: {enable: true, endpoint: /run/test}", "hostname-discovery: {enable: true, endpoint: relative, wait-ms: 50}", "hostname-discovery: {wait-ms: -1}", "hostname-discovery: {wait-ms: 251}"} {
		raw, err := UnmarshalRawConfig([]byte(text))
		if err == nil {
			_, err = parseGeneral(raw)
		}
		if err == nil {
			t.Fatalf("accepted invalid hostname settings: %s", text)
		}
	}
	raw, err := UnmarshalRawConfig([]byte("find-process-mode: off\n"))
	if err != nil {
		t.Fatal(err)
	}
	general, err := parseGeneral(raw)
	if err != nil || general.HostnameDiscovery.Enable {
		t.Fatal("hostname discovery enabled by default")
	}
	A.Default = A.New(nil)
	raw.HostnameDiscovery = A.Config{Enable: true, Endpoint: "/run/test", WaitMS: 50}
	if _, err := parseGeneral(raw); err == nil {
		t.Fatal("normal build silently enabled unavailable backend")
	}
}
