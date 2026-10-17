# Native application hostname lookup

Mihomo has an independent `hostname-discovery` configuration and a bounded
lookup in its native TCP REDIRECT path. Discovery is disabled by default and
does not depend on `find-process-mode`. The separately versioned reader is
included only in Linux amd64 builds with `hostname_discovery`; ordinary builds
reject an enabled configuration instead of silently accepting it.

This remains an experimental feature. The current observer supports an exact
OpenSSL socket-BIO/send path, not every application using that library. The base
profile leaves real curl 8.22.0/OpenSSL 3.5.3 custom-BIO traffic unattributed and
uses ordinary fallback. The separate opt-in [curl profile](../../socketowner/experiments/hostname/CURL.md)
verifies its exact custom-BIO/filter/socket chain and selects hostname DOMAIN
rules through confined TUN and local auto-redirect for both IP families and TLS
versions. TLS verification and observer-stop fallback remain intact. This covers
the tested direct TCP HTTP/1.1 build, not other curl paths or builds.

The observer is socketowner's separate
[`mihomo-hostname-observer`](../../socketowner/experiments/hostname/OBSERVER.md)
command; the existing `socketowner attach` command does not start it.
The [optional hostname contract v1](../../socketowner/docs/hostname-interface.md)
is separate from the process-owner ABI. The observer and its optional confined
service are installed separately. Keep the existing process owner loader setup
unchanged.

## Configuration

An experimental build accepts this configuration when a trusted observer is
available at the endpoint:

```yaml
find-process-mode: off
hostname-discovery:
  enable: true
  endpoint: /run/mihomo-hostname/bootstrap.sock
  wait-ms: 50
```

`endpoint` must be an absolute, canonical Unix pathname shorter than 108 bytes.
The reader separately verifies root ownership and permissions of the endpoint
and every parent directory, authenticates the server and obtains a kernel peer
pidfd. Configuration parsing does not open the socket.

Enabling requires an explicit `wait-ms` from 1 through 250. The example's value
is illustrative, not a measured recommendation. This is one absolute budget
for bootstrap, waiting for an eligible flow record and final post-match
validation. Repeated reads never extend it. A missing/rejected observer or
resource exhaustion can return unknown immediately; the budget is an upper
bound, not a promise to wait on every failure. Connections the observed process
did not open have no flow record at all; they return unknown after one read
instead of waiting. An in-progress kernel operation
or ordinary rule/preprocessing work can add elapsed time, but evidence returned
after the deadline cannot commit an application route.

Full configuration reload applies these settings independently of process
lookup. A committed reload, including an identical one, cancels pending reads
and revokes uncommitted evidence. Parsing or checking a proposed configuration
does not change the active hostname setting. Disabling does not reroute already
committed connections. The controller's general-config response reports the
active setting; no partial PATCH API is added by this change.

## Lookup and failure behavior

Only TCP REDIRECT and TUN connections with a real IP destination and no explicit
domain request lookup. Fake-IP, explicit inbound domain semantics, UDP, TPROXY
and internal traffic keep their existing paths. For REDIRECT the lookup takes the
accepted socket's namespace and full post-NAT endpoints, including local TCP
from `auto-redirect`: that listener labels connections REDIR. For TUN it takes the
`system` (or `mixed`) stack's original tuple in the namespace of the kernel socket
that stack accepted; the observer keyed the application's egress by the same
tuple. Native TCP from the `gvisor` stack has no kernel socket and returns
unknown. TUN flow matching across network namespaces is outside the validated
scope. Lookup
never uses process lookup's source-only owner map as hostname evidence.

A TUN tuple comes from packets the kernel routed into the device, not from an
accepted socket. A local process with CAP_NET_RAW could inject packets with an
observed connection's tuple; this can only affect the route of its own injected
connection, which can already choose any name through ordinary SNI.

Each attempt opens at most one authenticated reader and keeps that reader's
instance fixed through rule selection. It never adopts a replacement observer
for the same attempt. After the candidate is supplied, the existing
[metadata policy](application-hostname-metadata.md) performs source selection,
protects the real destination and revalidates after matching. An unusable or
revoked candidate restores ordinary metadata and policy before dialing.

At most 64 live readers span bootstrap and tentative evaluation. Capacity
exhaustion falls back immediately. Readers close on
failure, expiry, reload/disable, or immediately after final route selection;
map and pidfd descriptors are not retained by the relay. Polling uses one timer
per active attempt, with no waiting worker spawned for each map read.

This initial implementation opens descriptors per routing attempt rather than
pooling reader sessions. Throughput, latency under load and FD pressure are not
yet benchmarked. It does not request BPF-loading or process-inspection privileges
for Mihomo. Observation failure does not change the process loader or kill-switch.

## Development build and validation

The optional backend imports `github.com/nosini/socketowner/hostname`, a
separately versioned reader module requiring Go 1.25 or newer. It has no
experiment/loader module dependency. Normal builds keep the existing Go baseline
and omit the reader. `hostname_discovery_experimental` remains a build-tag alias
for existing development commands; both tags select the same reader.

From the Mihomo checkout, build with an explicit local reader checkout:

```sh
CGO_ENABLED=0 tools/with-hostname-reader.sh --reader-dir ../socketowner/hostname \
    build -tags hostname_discovery -o mihomo-hostname .
```

After a reader release is published, replace `--reader-dir` with
`--reader-version` and the exact release version (for example `v0.1.0` once that
release exists). No reader release has been published at this checkpoint.
The helper copies the ordinary go.mod/go.sum into a temporary build directory,
adds only the optional reader requirement/replacement there, and runs Go with
that modfile and `GOWORK=off`. It never edits the ordinary module files or installs
the observer. Build artifacts default to `bin/hostname-reader`; set an absolute
`HOSTNAME_BUILD_DIR` to use another project-specific scratch directory. It also
accepts `test`, `vet` and `list`, with normal Go flags. Pass all required feature
or integration-test tags explicitly.

For example, compile the route matrix without an experiment dependency:

```sh
tools/with-hostname-reader.sh --reader-dir ../socketowner/hostname \
    test -c -race -tags 'hostname_vm hostname_reader_vm hostname_discovery' \
    -o mihomo-route.test ./tunnel
```

When also building socketowner's tagged VM supervisor, put socketowner, its
nested `hostname` module and Mihomo in a temporary three-module workspace.
The supervisor alone needs the experimental package; the native Mihomo binary
and the direct-reader routing adapter use the independent reader module.

The native VM helper parses actual YAML configuration and uses the ordinary
tunnel lookup, without a wrapper supplying names or performing the lookup wait.
Its 32-case matrix covers both IP families and process modes, immediate/delayed
evidence, late evidence, absent/stalled observers, post-match disable/reload and
crash. It verifies route selection, original IP/port, ClientHello relay and no
remaining BPF-map/pidfd descriptors when the outbound dial starts.

Local race tests cover independent parsing, unavailable-backend rejection,
capacity, cancellation during bootstrap/polling, expiry, exactly-once cleanup,
and preservation of evidence while merely parsing another configuration.
A privileged bootstrap test cancels an authenticated connection while its server
withholds the reply. The existing routing matrices remain regression coverage.

The optional [hardened-service integration](https://github.com/nosini/hardened-proxy-service/blob/ebpf-hostname-discovery/docs/hostname-discovery.md)
provides a separately confined observer with tested stop/crash/restart behavior.
Its controlled IPv4/IPv6 matrix completes TLS 1.2/1.3, verifies certificates,
hostnames and certificate pins, rejects mismatches, and exchanges application
bytes while preserving the selected route and original destination. Both TLS
versions also pass ordinary fallback after observer stop or feature disablement.
The confined TUN and local nftables auto-redirect matrices also prove TLS ticket
resumption with new SSL objects and `SSL_clear` reuse onto new sockets for both
TLS versions and IP families.
Changed names select the corresponding domain rule, removed names use ordinary
routing, and observer-stop fallback still completes resumed TLS. Both peers
confirm actual resumption; repeated application exchanges preserve the committed
connection and route. No runtime or profile change was needed for these cases.
The same confined paths also complete forced TLS 1.3 key-share
HelloRetryRequest. Message counts prove two ClientHellos/one retry against a
one-ClientHello/no-retry control. Repeated exchanges preserve the connection
and route, including observer loss after initial route selection; new sockets
still use ordinary fallback. Wrong pins deliver no application request.
Controlled HTTP/2 over TLS 1.2/1.3 also passes concurrent streams
and later-stream reuse through both confined paths and families. Interleaved
requests/responses preserve the original connection, route and destination
through observer stop/restart; a new TLS hostname selects its own route.
Certificate, hostname and pin verification precede all HTTP/2 client bytes.
Explicit cross-origin reuse with hostnames sharing the fixture IP/port and
covered by the peer certificate preserves that original route, including on a
fallback connection. A fresh TLS SNI still selects its own rule. The test client
refuses an uncovered hostname before any HEADERS frame; valid origins can keep
using the verified connection afterward. A controlled 421 response on a coalesced
second-origin stream is recovered by retrying identical headers/path/body over
fresh verified TLS with that origin's SNI and own route. An open first-origin
sibling and subsequent streams retain the original connection/route. The
fixture explicitly drives this retry; browser retry decisions remain unproved.
This does not add per-stream routing or prove browser cross-origin coalescing.
Broader sends, reinjection, early data, cookie-only HRR, automatic browser coalescing,
browser encrypted-DNS/ECH and production performance validation remain open.

The current reader and observer require [hostname contract profile 3](../../socketowner/hostname/PROFILE3.md).
It admits one complete initial ClientHello record up to 16 KiB and verified
retries within its original remaining bytes, on the same live SSL connection
with the same name. Larger ClientHellos and actual short-write retries pass
TLS 1.2/1.3 through the confined services. Unsupported later writes still revoke
discovery authority without interrupting an already committed relay.

Rebuild both the observer and optional reader consumer when upgrading from
profiles 1 or 2. A mismatched observer returns unknown; the normal Mihomo module
graph and process-owner ABI remain unchanged. The limit is 256 concurrently
retained socket lifetimes, reclaimed only after final release and callback drain.
Local nftables `auto-redirect` is also tested for both IP families with healthy,
delayed and missing evidence, observer death after matching, unobserved senders,
completed TLS/resumption and forced source-port collisions. The accepted
post-NAT source and destination distinguish simultaneous flows even when their
original source ports coincide. The tests assert REDIR metadata and the actual
redirect listener port. No adapter or routing change was needed; previous docs
incorrectly described this path as unknown. Forwarded/prerouting, bridge and
iptables-fallback paths remain unproved.

The adapter still supports one exact OpenSSL build and target process; browser
TLS stacks, ECH-inner names and additional interception modes remain unsupported.

Confined IPv6 TUN and auto-redirect regression testing exposed an upstream
policy-rule ordering bug: initial connects chose the TUN, but later lookups
with the socket's chosen source address skipped its table. Mihomo's Linux TUN
constructor moves sing-tun's two blanket bypass rules behind its existing
TUN-source lookups, within the same owned priority range. The upstream module
stays unchanged and normal listener cleanup removes the adjusted rules. Service tests assert both lookup
forms and flush the route cache between application exchanges on one live TLS
connection. The kill switch and hostname authority checks stay unchanged.
