//go:build linux && amd64 && hostname_vm && hostname_reader_vm

package tunnel_test

import (
	"net/netip"
	"time"

	E "github.com/nosini/socketowner/hostname"
)

type hostnameVMDirectReader struct{ *E.Reader }

func (r hostnameVMDirectReader) Lookup(netns uint64, source, destination netip.AddrPort, deadline time.Time) (string, func() bool, error) {
	candidate, err := r.Reader.Lookup(E.TCPFlow{Netns: netns, Source: source, Destination: destination}, deadline)
	if err != nil {
		return "", nil, err
	}
	return candidate.Name(), func() bool { return candidate.Validate() == nil }, nil
}

func init() {
	hostnameVMOpenReader = func(path string, deadline time.Time) (hostnameVMReader, error) {
		r, err := E.DialReader(path, deadline)
		if err != nil {
			return nil, err
		}
		return hostnameVMDirectReader{r}, nil
	}
}
