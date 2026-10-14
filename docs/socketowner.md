# Linux socket-owner lookup

mihomo can read connection owners and executable paths from pinned BPF maps,
without BPF capabilities or permission to inspect other processes. The privileged
loader is maintained, built and installed separately in the
[socketowner repository](https://github.com/nosini/socketowner).

[hardened-mihomo-service](https://github.com/nosini/hardened-mihomo-service#process-lookup)
provides deployment units, read-only map mounts, reader permissions and SELinux
policy. Building or installing mihomo does not build or install the loader.

## Configuration

```yaml
find-process-mode: strict
find-process-bpf-map: /sys/fs/bpf/mihomo/maps/conn_owners
find-process-bpf-only: true
```

Use the path visible to mihomo; the hardened service uses
`/run/mihomo-bpf/conn_owners` instead. `find-process-bpf-only: true` disables both
netlink and `/proc` fallback, so executable matching needs the loader's
`-exec-paths` option. With it set to false, mihomo falls back to ordinary process
lookup when maps or records are unavailable. An empty map path disables BPF
lookup.

## Compatibility

This reader supports [socketowner map interface v1](https://github.com/nosini/socketowner/blob/main/docs/map-interface.md).
It requires `abi_version` beside `conn_owners`, checks its value before opening
connection records, and validates the type and sizes of every map it opens. A
missing or unsupported marker prevents BPF lookup and produces a warning; the
configured fallback policy still applies. It opens all maps read-only and does
not depend on the loader's Go module or cilium/ebpf.

Loader releases and mihomo releases need not have matching version
numbers; their supported map ABI must match.

## Integration tests

The unprivileged reader and process-matching tests live here. Object and loader
tests live in socketowner. To run the integration suite on a disposable Linux
machine with BPF capabilities and an active BPF LSM, first attach the separately
built loader with `-exec-paths`, then build from this checkout:

```sh
go test ./component/process
go test -c -tags sockowner_vm -o process.test ./component/process
sudo env SOCKOWNER_MAP=/sys/fs/bpf/mihomo/maps/conn_owners \
    ./process.test -test.v -test.run 'SockOwner|ExecPath|ExecMaps'
```

A dedicated loader `-pin` directory can be used with the corresponding
`SOCKOWNER_MAP`. Stop the test loader afterwards with the same `-pin` and `detach`.
