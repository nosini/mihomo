# Linux socket-owner lookup

mihomo can read connection owners and executable paths from pinned BPF maps,
without BPF capabilities or permission to inspect other processes. The privileged
loader is maintained, built and installed separately in the
[socketowner repository](https://github.com/nosini/socketowner).

[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service#process-lookup)
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

It also reads socketowner's optional Windows identity maps, pinned beside the
others by its Wine observer. A flow they cover keeps the process holding its
socket, such as a sandbox's pasta, and adds the Windows program in separate
`wineProcess` and `wineProcessPath` fields; one they can't identify reports
`wine-unknown` there. `WINE-PROCESS-NAME`, `WINE-PROCESS-PATH` and their
`-REGEX` and `-WILDCARD` forms match these fields as the `PROCESS-*` rules match
the process, ignoring case. A flow without a Wine record matches none of them,
not even `*` or `.*`:

```yaml
rules:
  # Only this program, only from this sandbox, goes direct
  - AND,((PROCESS-NAME-REGEX,^game-pasta(\.avx2)?$),(WINE-PROCESS-NAME,game.exe)),DIRECT
  - WINE-PROCESS-NAME,tbs_browser.exe,REJECT
  # The rest of the sandbox, including unknown and unrecorded flows
  - PROCESS-NAME-REGEX,^game-pasta(\.avx2)?$,PROXY
```

A broad `PROCESS-*` rule for a relay matches every program behind it, so place
rules refusing a Windows program before it. 32-bit clients have a name but no
Windows path. The reader and observer are available on their respective `main`
branches.

socketowner records host process IDs, so the reader only resolves process
paths when mihomo runs in the initial PID namespace. In a nested PID namespace
it still reports the owner's UID, but leaves the process name and path empty
and logs one warning instead of looking up an unrelated process.

This build also disables the hub's core self-update (`POST /upgrade`), which
would replace it with stock MetaCubeX. Geo database updates are unchanged.

The reader requires `abi_version` beside `conn_owners`, checks its value before opening
connection records, and validates the type and sizes of every map it opens. A
missing or unsupported marker prevents BPF lookup and produces a warning; the
configured fallback policy still applies. It opens all maps read-only and does
not depend on the loader's Go module or cilium/ebpf.

Loader releases and mihomo releases need not have matching version
numbers; their supported map ABI must match.

## Lookup health

`GET /process-lookup` on the external controller reports whether process lookup
is working and where its answers come from. It sits beside the other routes and
asks for the same authentication; on builds for other systems it answers with
`supported: false` and a message instead. Answering it opens the maps like a
lookup does, so it also notices a loader that started after mihomo, and it costs
one map lookup for the Wine heartbeat.

```json
{
  "supported": true,
  "bpfOnly": false,
  "mapPath": "/run/mihomo-bpf/conn_owners",
  "maps": {
    "open": true,
    "abiVersion": 1,
    "execMapsOpen": true
  },
  "wine": {
    "present": true,
    "abiVersion": 2,
    "heartbeatAgeSeconds": 1,
    "stale": false
  },
  "counters": {
    "bpfHits": 21,
    "bpfMisses": 3,
    "procFallbacks": 2,
    "wineKnown": 5,
    "wineUnknown": 1,
    "wineStaleRefused": 0
  }
}
```

The error fields are left out while everything opens; a broken setup adds them,
for example after installing a loader with an unsupported map interface:

```json
{
  "supported": true,
  "bpfOnly": true,
  "mapPath": "/run/mihomo-bpf/conn_owners",
  "maps": {
    "open": false,
    "abiVersion": 0,
    "error": "socketowner ABI (install a compatible socketowner loader): unsupported ABI v2 in /run/mihomo-bpf/abi_version (need v1)",
    "execMapsOpen": false,
    "execMapsError": "open /run/mihomo-bpf/exec_tasks: no such file or directory"
  },
  "wine": {
    "present": false,
    "abiVersion": 0,
    "stale": false
  },
  "counters": {
    "bpfHits": 0,
    "bpfMisses": 0,
    "procFallbacks": 0,
    "wineKnown": 0,
    "wineUnknown": 0,
    "wineStaleRefused": 0
  }
}
```

The fields:

- `bpfOnly` mirrors `find-process-bpf-only`, and `mapPath` the configured map,
  which is empty when BPF lookup is off.
- `maps.open` is true while the socket-owner map is open, and `maps.abiVersion`
  is the interface version it was validated against, 0 while closed.
  `maps.error` holds the last error from opening or validating the maps, such as
  an unsupported ABI version. It is empty while they are open, and also when
  nothing is pinned at the configured path yet, because a loader may start
  later. `maps.execMapsOpen` and `maps.execMapsError` report the exec-path maps
  the same way; while they are open, executable paths are resolved without
  reading `/proc`.
- `wine.present` is true while the Wine maps are open and `wine.abiVersion` is
  their version. `wine.heartbeatAgeSeconds` is the age of the observer's
  heartbeat in seconds, left out when it cannot be read and negative when the
  heartbeat is ahead of the boot clock, which proves nothing. `wine.stale`
  reuses the reader's five-second limit: while it is set, flows with a Wine
  record match `WINE-PROCESS-*` rules as `wine-unknown`, and the counter below
  counts the lookups refused for that reason.
- The counters grow from process start and are never reset. `bpfHits` and
  `bpfMisses` count the lookups that consulted the maps; `procFallbacks` counts
  the ones that went through netlink and the `/proc` search instead, which never
  happens with `bpfOnly`. `wineKnown` and `wineUnknown` count the Wine records
  found, by whether the Windows program could be established.

Wine publication problems are also logged, once per change rather than per
lookup. A warning says the heartbeat went stale or that the maps disappeared
after they had been present, and an info line says they came back; `<dir>` is
the directory of the Wine maps:

```text
[Process] Wine heartbeat in <dir> is stale; covered flows match as wine-unknown
[Process] Wine maps in <dir> disappeared; WINE-PROCESS rules match nothing until they return
[Process] Wine maps in <dir> are back; the heartbeat is fresh
[Process] Wine heartbeat in <dir> is fresh again
```

The first two are warnings, the last two info lines. The publication state is
checked while connections are resolved, at most once every five seconds, and
every time the endpoint answers; nothing runs in the background, so reloading
the configuration leaves no work behind. A change of `find-process-bpf-map`
starts the observations over, so it logs nothing for the maps' first state.

## Integration tests

The unprivileged reader and process-matching tests live here. Object and loader
tests live in socketowner. To run the integration suite on a disposable Linux
machine with BPF capabilities and an active BPF LSM, first attach the separately
built loader with `-exec-paths`, then build the assembled source from this checkout:

```sh
make test-process
make test-vm
sudo env SOCKOWNER_MAP=/sys/fs/bpf/mihomo/maps/conn_owners \
    ./bin/process.test -test.v -test.run 'SockOwner|ExecPath|ExecMaps'
```

A dedicated loader `-pin` directory can be used with the corresponding
`SOCKOWNER_MAP`. Stop the test loader afterwards with the same `-pin` and `detach`.
