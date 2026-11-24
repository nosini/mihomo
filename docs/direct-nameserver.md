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
- When every nameserver of an outbound fails, the connection fails. The
  lookup is never answered by `dns.direct-nameserver`, the main
  `dns.nameserver` list or the system resolver instead.
- Reloading the configuration discards the cache. Flushing the DNS cache
  through the API does not clear it.

## Connection metadata

A connection whose destination a direct outbound resolved through its own
nameservers carries an `outboundDns` group in the metadata reported by
`GET /connections`, the connections websocket and the dashboard's connection
list. Connections resolved another way, by the `dns` section, a hosts entry
or a direct outbound without the option, carry nothing.

- `server` is the nameserver that answered, in `dns.nameserver` form with the
  port mihomo uses, so an entry written as `udp://10.0.0.53` is reported as
  `udp://10.0.0.53:53`.
- `localAddr` is the source address of the query as its transport reports it.
  UDP and TCP queries report the address of the socket that sent the query,
  which for UDP can be the wildcard address with the source port the
  nameserver sees. `tls`, `https` and `quic` queries report no local address.
- `interface` is the outbound's `interface-name` the query was bound to. It
  is left out when the outbound has none, and for nameservers on loopback
  addresses, which mihomo does not bind (see Limitations).
- `cached` is true when the answer came from the outbound's cache. The other
  values are then those of the query that filled the entry, and no query
  leaves mihomo.

```json
{
  "id": "0f4c1b6e-4f88-4d21-9b0e-5f1a2b3c4d5e",
  "metadata": {
    "network": "tcp",
    "type": "Socks5",
    "sourceIP": "192.168.1.23",
    "destinationIP": "203.0.113.10",
    "sourcePort": "51423",
    "destinationPort": "443",
    "host": "example.org",
    "process": "curl",
    "outboundDns": {
      "server": "udp://10.0.0.53:53",
      "localAddr": "10.0.0.5:53712",
      "interface": "eth0.110",
      "cached": true
    }
  },
  "start": "2026-11-24T18:30:00Z",
  "chains": ["exit-a"],
  "rule": "Match",
  "rulePayload": ""
}
```

With several nameservers configured, the group names the one that first
answered the lookup. A dual-stack lookup sends an A and an AAAA query; the
group reports the first of them that was answered.

Every query that leaves through the outbound is logged at debug level, one
line per query, with the outbound name, the host, the nameserver, the local
address and the answer's rcode or the error:

```text
[DNS] exit-a: example.org queried via udp://10.0.0.53:53 (local 10.0.0.5:53712): NOERROR
[DNS] exit-a: example.org queried via udp://10.0.0.53:53 (local 10.0.0.5:53712): read: connection refused
```

Cache hits are not queries and log nothing.

## Verifying

To confirm that a connection's DNS left through its exit, open the
connection list while a connection through the exit is up and read the
connection's `outboundDns` group:

- `server` names one of the exit's own nameservers, never a server from the
  `dns` section.
- `interface` names the exit's `interface-name`.
- `cached` tells whether the answer needed a query; when it is true, the
  remaining values describe the earlier query that filled the cache entry.

The DNS server's own query log completes the picture: the query for the
connection's host must arrive there, from the source address in `localAddr`
over the exit's interface. The `dns` section's servers must show no query
for the host. Running mihomo with `log-level: debug` adds one line per query
that left through the exit, as shown above, which is enough to follow
resolution without any external service.

A connection through a second exit with its own nameserver shows that exit's
server in its `outboundDns` group, and each server's log shows only the
queries of the exit configured with it. When every nameserver of an exit
fails, its connections fail outright: the dial reports the DNS error, and no
other resolver answers in their place.

## Limitations

The option only exists for direct outbounds. Proxy outbounds that receive a
hostname, such as SOCKS5, pass the name on and the far end resolves it.

mihomo does not bind loopback or other non-global destinations to
`interface-name`, so a nameserver on such an address is reached through the
routing table rather than the outbound's interface. Private addresses such as
`10.0.0.53` are bound.
