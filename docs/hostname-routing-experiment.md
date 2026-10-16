# Application hostname routing experiment

The `hostname_vm`-tagged test in `tunnel/hostname_vm_test.go` is a companion to
socketowner's private OpenSSL hostname experiment. It runs Mihomo's real Linux
REDIRECT listener, TCP tunnel, DOMAIN matcher, DIRECT adapter and relay under a
supervising VM test. There is no production hostname configuration or reader.

The supervisor owns all BPF state and supplies validated lookup results over an
inherited Unix socket. A test-only tunnel wrapper waits at most one absolute
250 ms budget before handing the connection to Mihomo. A rule wrapper evaluates
the resulting name using a metadata clone, preserving the original dial IP and
port. This isolates timing and destination behavior while leaving production
provenance, precedence and observer authority undecided.

The matrix covers IPv4/IPv6 and process lookup `off`/`always`. It demonstrates
that current routing can choose its outbound before ClientHello: the background
200 ms peek does not delay rule selection. The bounded experiment selects the
named outbound for early evidence and fallback for late/missing evidence, stopped
observers, stalled requests and positive replies arriving after the deadline.
Each case verifies the real dial and ClientHello relay to the original IP/port,
and rejects a second dial after commitment.

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
private cgroup. They explicitly enable IPv6 and disable sniffing. The peer stops
after reading ClientHello. Full TLS/certificate validation, Fake-IP/sniffer
precedence, encrypted DNS, ECH, browser support, independent observer crash safety,
a versioned ABI and least-privilege deployment remain unverified.
