package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
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

// withLookupTrace attaches a query trace to ctx when this outbound resolves
// the destination with its own nameservers, so the lookup can report which
// nameserver answered. It returns ctx unchanged for everything that resolves
// elsewhere: inner queries to the outbound's own nameservers, dials that
// were given an address, and outbounds without a nameserver list.
func (d *Direct) withLookupTrace(ctx context.Context, metadata *C.Metadata) (context.Context, *dns.QueryTrace) {
	if d.resolver == nil || metadata.Host == "" {
		return ctx, nil
	}
	trace := dns.NewQueryTrace(d.Name())
	return dns.WithQueryTrace(ctx, trace), trace
}

// recordLookup copies how the lookup answered into the connection's metadata.
// It runs during the dial: the tracker that exposes the metadata joins the
// connection manager only after DialContext or ListenPacketContext returns,
// so this write cannot race with readers of the connection list.
func (d *Direct) recordLookup(trace *dns.QueryTrace, metadata *C.Metadata) {
	if trace == nil {
		return
	}
	server, localAddr, cached, ok := trace.Result()
	if !ok {
		return
	}
	dnsMetadata := &C.OutboundDNS{
		Server:    server,
		LocalAddr: localAddr,
		Cached:    cached,
	}
	// mihomo does not bind loopback destinations to the interface, so a
	// nameserver on such an address is reached through the routing table.
	if d.iface != "" && !nameServerOnLoopback(server) {
		dnsMetadata.Interface = d.iface
	}
	metadata.OutboundDNS = dnsMetadata
}

// nameServerOnLoopback reports whether a nameserver address as the client
// reports it names a loopback host.
func nameServerOnLoopback(server string) bool {
	u, err := url.Parse(server)
	if err != nil {
		return false
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
