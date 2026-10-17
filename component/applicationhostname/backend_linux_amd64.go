//go:build hostname_discovery || hostname_discovery_experimental

package applicationhostname

import (
	"context"
	"time"

	E "github.com/nosini/socketowner/hostname"
)

type hostnameReader struct{ *E.Reader }

func (r hostnameReader) Lookup(flow Flow, deadline time.Time) (Candidate, error) {
	return r.Reader.Lookup(E.TCPFlow{Netns: flow.Netns, Source: flow.Source, Destination: flow.Destination}, deadline)
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
