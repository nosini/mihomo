package outbound

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
)

// newDirectResolver builds the resolver used for a direct outbound's own
// connections. Its queries are sent through the outbound, so they leave with
// the outbound's interface-name and routing-mark. It has its own cache and
// query deduplication, separate from every other resolver.
//
// Nameserver addresses must be IP addresses: a hostname would need a lookup
// outside the outbound before the outbound could reach its own nameserver.
// Entries are dialed through the outbound with the address already resolved,
// so they never re-enter the outbound's own resolution.
func newDirectResolver(servers []string, d *Direct) (resolver.Resolver, error) {
	if dns.ParseNameServer == nil {
		return nil, errors.New("nameserver parsing is unavailable")
	}
	nss, err := dns.ParseNameServer(servers)
	if err != nil {
		return nil, err
	}
	for i := range nss {
		if err := checkDirectNameServer(nss[i]); err != nil {
			return nil, fmt.Errorf("nameserver[%d]: %w", i, err)
		}
		nss[i].ProxyAdapter = d
	}
	return dns.NewResolver(dns.Config{
		Main: nss,
		IPv6: true, // ip-version and the global ipv6 switch choose the families
	}).Resolver, nil
}

func checkDirectNameServer(ns dns.NameServer) error {
	if ns.ProxyName != "" {
		return fmt.Errorf("%q: a proxy or interface after '#' is not allowed; queries always use this outbound", ns.ProxyName)
	}
	addr := ns.Addr
	switch ns.Net {
	case "", "tcp", "tls", "quic":
	case "https":
		u, err := url.Parse(addr)
		if err != nil {
			return err
		}
		addr = u.Host
	default:
		return fmt.Errorf("scheme %q is not supported; use udp, tcp, tls, https or quic", ns.Net)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("%q is not an IP address", host)
	}
	return nil
}

// Close drops the connections held by the outbound's own nameservers.
func (d *Direct) Close() error {
	if r, ok := d.resolver.(interface{ ResetConnection() }); ok {
		r.ResetConnection()
	}
	return d.Base.Close()
}
