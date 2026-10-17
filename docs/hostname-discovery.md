# Native application hostname lookup

Mihomo has an independent `hostname-discovery` configuration and a bounded
lookup in its native TCP REDIRECT path. Discovery is disabled by default and
does not depend on `find-process-mode`. The separately versioned reader is
included only in Linux amd64 builds with `hostname_discovery`; ordinary builds
reject an enabled configuration instead of silently accepting it.

This remains an experimental feature. The observer is socketowner's separate
[`mihomo-hostname-observer`](../../socketowner/experiments/hostname/OBSERVER.md)
command; the existing `socketowner attach` command does not start it.
The [optional hostname contract v1](../../socketowner/docs/hostname-interface.md)
is separate from the process-owner ABI. There is no installed observer service.
Keep the existing process owner loader and service setup unchanged.

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
bound, not a promise to wait on every failure. An in-progress kernel operation
or ordinary rule/preprocessing work can add elapsed time, but evidence returned
after the deadline cannot commit an application route.

Full configuration reload applies these settings independently of process
lookup. A committed reload, including an identical one, cancels pending reads
and revokes uncommitted evidence. Parsing or checking a proposed configuration
does not change the active hostname setting. Disabling does not reroute already
committed connections. The controller's general-config response reports the
active setting; no partial PATCH API is added by this change.

## Lookup and failure behavior

Only TCP REDIRECT connections with a real IP destination and no explicit domain
request lookup. Fake-IP, explicit inbound domain semantics, UDP, TUN, TPROXY and
internal traffic keep their existing paths. The lookup takes the accepted
socket's namespace and full post-NAT endpoints; it never uses process lookup's
source-only owner map as hostname evidence.

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
tools/with-hostname-reader.sh --reader-dir ../socketowner/hostname \
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

Production use still needs an independently managed observer with tested
service confinement/restart behavior. Broader sends,
reinjection, completed TLS and browser encrypted-DNS/ECH support remain open.
