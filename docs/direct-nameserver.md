# Nameservers for direct outbounds

A `type: direct` outbound can have its own `nameserver` list. When the outbound
connects to a hostname, it looks the name up with these servers, and the DNS
queries themselves leave through the outbound, with its `interface-name` and
`routing-mark`. The DNS server then sees the same source address as the
connection that follows.

Without the option, a direct outbound resolves hostnames with the shared
resolver for direct connections (`dns.direct-nameserver`, or `dns.nameserver`
when that is unset). Those queries leave through the default route, whichever
interface the outbound is bound to.

## Configuration

```yaml
proxies:
  - name: exit-a
    type: direct
    udp: true
    interface-name: eth0.110
    nameserver: [udp://10.0.0.53]

  - name: exit-b
    type: direct
    udp: true
    interface-name: eth0.120
    routing-mark: 120
    nameserver:
      - tls://10.0.0.53
      - https://10.0.0.53/dns-query
```

Entries use the `dns.nameserver` syntax with the `udp`, `tcp`, `tls`, `https`
and `quic` schemes, including their `#` parameters such as `disable-ipv6=true`.
A bare address means `udp://`. These entries are refused:

- A hostname as the server address. Looking it up would need a query outside
  the outbound, so the address must be an IP address.
- A proxy or interface name after `#`. Queries always go through the outbound
  that owns the list.
- `system`, `dhcp`, `rcode`, `tailscale` and `easytier`, which do not send
  queries through an outbound.

The outbound's `ip-version` and the global `ipv6` setting choose which address
families are looked up. `dns.ipv6` does not apply to these servers.

## Behavior

- Both TCP connections and UDP sessions use the outbound's servers.
- Each outbound has its own answer cache and merges only its own identical
  queries. A name looked up through one outbound is not answered from another
  outbound's cache, so two outbounds that share a server each send their query.
- When a rule matched the connection by IP address, the destination was already
  resolved by the main resolver. The outbound looks the hostname up again with
  its own servers and connects to that answer, as `direct-nameserver` does.
- The queries appear in the connection list as inner connections through the
  outbound.
- Fake-IP answers given to applications, and lookups made while matching
  rules, still use the `dns` section.
- `DIRECT` and direct outbounds without the option behave as before, and
  `direct-nameserver` keeps its meaning for them.
- Reloading the configuration discards the cache. Flushing the DNS cache
  through the API does not clear it.

## Limitations

The option only exists for direct outbounds. Proxy outbounds that receive a
hostname, such as SOCKS5, pass the name on and the far end resolves it.

mihomo does not bind loopback or other non-global destinations to
`interface-name`, so a nameserver on such an address is reached through the
routing table rather than the outbound's interface. Private addresses such as
`10.0.0.53` are bound.
