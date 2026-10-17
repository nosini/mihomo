//go:build hostname_discovery || hostname_discovery_experimental

package applicationhostname

import (
	"context"
	"errors"
	"time"

	E "github.com/nosini/socketowner/hostname"
)

type hostnameReader struct{ *E.Reader }

func (r hostnameReader) Lookup(flow Flow, deadline time.Time) (Candidate, error) {
	candidate, err := r.Reader.Lookup(E.TCPFlow{Netns: flow.Netns, Source: flow.Source, Destination: flow.Destination}, deadline)
	if errors.Is(err, E.ErrNoFlow) {
		return nil, ErrNoFlow
	}
	if err != nil {
		return nil, err
	}
	return candidate, nil
}
func init() {
	Default = New(func(ctx context.Context, endpoint string, deadline time.Time) (Reader, error) {
		reader, err := E.DialReaderContext(ctx, endpoint, deadline)
		if err != nil {
			return nil, err
		}
		return hostnameReader{reader}, nil
	})
}
