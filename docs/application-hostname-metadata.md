# Application hostname routing metadata

Mihomo now has an internal, optional application-hostname field consumed by
`Metadata.RuleHost()`. It is separate from `Host` and `SniffHost`. The native
[hostname lookup](hostname-discovery.md) has independent disabled-by-default
configuration and requires an explicit experimental backend build. Ordinary
builds have no backend and reject enabling it. The supervised `hostname_vm` experiment exercises the path with
the existing domain matcher instead of substituting a cloned rule input.

This is a routing semantic contract, not a public BPF layout or service protocol.
The socketowner diagnostic maps and bootstrap remain experimental.

## Association and provenance

`SetApplicationHostname` takes a reader-validated name, a required fresh-validation
callback and an explicit role:

- `ApplicationHostnameTLS`: a supported adapter verified the ordinary TLS name.
- `ApplicationHostnameECHInner`: an adapter verified the intended ECH inner
  name. A difference from sniffed SNI is insufficient to establish this role.

The current OpenSSL experiment supplies only the first role. No browser or ECH
adapter is implemented by this change.

Names must be complete ASCII DNS hostnames, with labels of 1–63 bytes and a
maximum of 253 bytes after removing one terminal root dot. Case is folded.
IP literals, empty labels, whitespace, embedded NUL, wildcard/underscore labels,
leading/trailing label hyphens and non-ASCII bytes are rejected. There is no
truncation, whitespace trimming or implicit IDNA conversion.

The immutable local record binds to the accepted source/destination addresses
and ports. Only TCP REDIRECT is admitted; changing its tuple, network or inbound
type makes it unusable. Different repeated observations, including a malformed
replacement, permanently exclude application evidence on that metadata.
`Clone()` can share the immutable record without allowing a clone to alter it.

These local checks do not prove socket identity, observer liveness or publisher
authority. The reader must establish those and validate freshness at route
commitment. A copied name is not a durable authority token. The extra
`hostname_reader_vm` companion now connects the authenticated socketowner reader
directly to capability-free Mihomo and rechecks its candidate after rule matching.
The final guarded read is the commitment point; it does not grant an authority
lease covering subsequent process/kernel events or the outbound handshake.

If preparation or confirmation fails, source selection rejects the candidate,
or route evaluation returns an error, the tunnel
restores a snapshot from before application-dependent processing and selects once
without application evidence. This reapplies ordinary DNS/Fake-IP, hosts and
sniffer policy before dialing. The failed candidate cannot heal, and identical
text cannot replace its original authority callback. Ordinary preprocessing and
sniffing may run once more with their existing deadlines; the background peek
runs only on the final attempt. This is not a production latency policy.

## Source selection

When no usable application evidence is present, `RuleHost()` retains its existing
choice: `SniffHost` if present, otherwise `Host`.

| Existing metadata | Application evidence | Result |
| --- | --- | --- |
| Explicit destination name or hosts destination | Any | Existing Host/SniffHost semantics |
| Valid Fake-IP mapping | Any | Existing Fake-IP and sniffer semantics |
| Real destination IP, no conflicting sniff | Verified TLS name | Application name |
| Real destination IP with DNSMapping hint | Verified name | Application name takes precedence over the IP-to-name hint |
| Different ordinary sniffed name | Ordinary TLS name | Application evidence is unusable; existing sniffing applies |
| Different outer SNI | Adapter-verified ECH inner name | Inner name |
| Missing, invalid or conflicting application association | Any | Existing routing |

An explicit name is not demoted to an IP-to-name hint just because an application
name exists. Missing Fake-IP mappings still fail preprocessing; application
evidence cannot turn a fake address into a real dial target.

## Destination preservation

A usable application name changes domain-rule selection only. It preserves the
application-selected real IP and port through DNS mapping preprocessing, hosts
overrides and sniffing, including `override-destination: true`. Sniffing still
records its result so ordinary-name conflicts can be detected. A conflict falls
back to the existing sniffer policy, including destination replacement if enabled.

For a selected application association, `Pure()` supplies a dial clone with an
empty `Host`. The real IP survives DIRECT dialing and proxy address encoding.
The application name is never assigned to `Host`, resolved through DNS or used
as an outbound address. Existing explicit-name and Fake-IP dialing is unchanged.

The private field is excluded from JSON, so it adds no connection-history field
or way to inject authority through JSON metadata. This does not change existing
logging of rule payloads or other metadata. Routes stay fixed after commitment.

## Validation and remaining work

Local race tests cover normalization, tuple/type exclusions, repeated-observation
conflicts, cloning, ordinary domain matching, dial/JSON encoding, sniffer
override policies and IPv4/IPv6 Fake-IP preprocessing with a controlled pool.
The VM matrix covers 32 real REDIRECT cases: both IP families and process lookup
off/always, existing deadline/failure cases, TLS sniffing with destination
replacement enabled, and conflicting DNS hints/hosts entries. Each checks the
real route, dial destination and ClientHello relay. These are correctness tests,
not latency benchmarks.

An additional 36-case direct-reader VM matrix covers healthy authority,
post-match crash/revocation/second-send/eviction/expiry/reader-close/restart, and
a post-commit crash. Both IP families and process modes are covered. The helper
receives maps via authenticated bootstrap, rather than inheriting capabilities
or receiving positive names from the supervisor. Local tests also cover
post-match metadata rollback and restoration of ordinary hosts policy. See
[the consumption experiment](../../socketowner/experiments/hostname/CONSUMPTION.md)
for scope and build instructions using a temporary two-module Go workspace.

The native lookup now supplies independent configuration, a bounded wait and
reload/disable cancellation. Production integration still needs a stable optional
reader interface, packaging, a resident observer entry point and service
confinement. UDP, TUN,
TPROXY and explicit proxy observation remain excluded. Broader sends,
reinjection, completed TLS and browser encrypted-DNS/ECH workloads remain open.
