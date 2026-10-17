# Application hostname routing experiment

The `hostname_vm`-tagged test in `tunnel/hostname_vm_test.go` is a companion to
socketowner's private OpenSSL hostname experiment. It runs Mihomo's real Linux
REDIRECT listener, TCP tunnel, DOMAIN matcher, DIRECT adapter and relay under a
supervising VM test. There is no production hostname configuration or reader.

The supervisor owns all BPF state and supplies validated lookup results over an
inherited Unix socket. A test-only tunnel wrapper waits at most one absolute
250 ms budget before handing the connection to Mihomo. It supplies a validated
ordinary TLS name through the internal application-hostname metadata. The normal
`RuleHost()` and DOMAIN matcher select the route while preserving the original
dial IP and port. [Metadata semantics](application-hostname-metadata.md) define
provenance and precedence. The extra direct-reader companion described below
adds final-consumption authority checks; production configuration remains open.

The matrix covers IPv4/IPv6 and process lookup `off`/`always`. It demonstrates
that current routing can choose its outbound before ClientHello: the background
200 ms peek does not delay rule selection. The bounded experiment selects the
named outbound for early evidence and fallback for late/missing evidence, stopped
observers, stalled requests and positive replies arriving after the deadline.
Each case verifies the real dial and ClientHello relay to the original IP/port,
and rejects a second dial after commitment. The expanded matrix has 32 cases,
including TLS sniffing with destination replacement enabled and conflicting DNS
hints/hosts entries. Both test binaries pass with Go's race detector.

Build the helper from this checkout:

```sh
go test -c -tags hostname_vm -o "$route_build/mihomo-route.test" ./tunnel
```

Transfer it into the verified test VM alongside socketowner's test binary and
experiment artifacts; set `HOSTNAME_VM_MIHOMO` in that supervisor to its path.
The companion `experiments/hostname/ROUTING.md` contains the complete invocation
and supported profile. Running this helper directly without the supervisor skips
the test. Ordinary Mihomo builds exclude the helper entirely.

The tests use an isolated network namespace and redirect only the client's
private cgroup. They explicitly enable IPv6; sniffing runs only in its dedicated
case. The peer stops after reading ClientHello. Full TLS/certificate validation,
end-to-end Fake-IP, encrypted DNS, ECH and browser support remain unverified.
The extra `hostname_reader_vm` build now bootstraps socketowner's authenticated
reader directly in capability-free Mihomo. Its 36-case matrix adds post-match
validation, rollback before dialing and fixed routes after commitment. It uses a
temporary Go workspace containing the independent reader module, with no ordinary
Mihomo module dependency. See [CONSUMPTION.md](../../socketowner/experiments/hostname/CONSUMPTION.md)
for the build, budgets and tested failure points. Both routing matrices pass
together under the race detector. The [versioned reader module](../../socketowner/hostname/README.md)
and resident observer command now exist; observer service confinement remains open. The
[native lookup](hostname-discovery.md) adds independent configuration and a
bounded wait through the ordinary tunnel in experimental backend builds.
