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

## Flatpak apps

Loaders that publish owner cgroups (feature bit 0 of `abi_version`, the
`conn_cgroups` map) let mihomo name the cgroup v2 of the process that owns a
connection. `FLATPAK-APP` matches the Flatpak app whose scope that cgroup is
in:

```yaml
rules:
  - FLATPAK-APP,org.jdownloader.JDownloader,PROXY
```

`flatpak run` in a desktop session starts each app in a transient systemd scope,
`app-flatpak-<app ID>-<instance>.scope`, with the app ID escaped as a unit name
(`-` becomes `\x2d`). Older Flatpak versions used the unescaped ID and the
process ID; both forms are recognised. Only the owner's own cgroup or its
nearest ancestor named `app-flatpak-…` counts. When that name isn't a valid
scope for a valid app ID, the app is unknown, and no component further up is
tried. App IDs are compared exactly, as Flatpak does; a rule whose payload isn't
a valid app ID is rejected when the configuration loads. The lookup runs where
process lookup runs, so `find-process-mode: off` turns the rule off too.

Connections attributed this way show the cgroup in `cgroupPath`, relative to the
cgroupfs root, and the app in `flatpakApp`, beside `process` and `processPath`
in the connection list; log lines add `flatpak=<app ID>` to the source.

### Systemd units and Podman containers

`SYSTEMD-UNIT` matches the systemd service or scope whose cgroup holds the
connection's owner:

```yaml
rules:
  - SYSTEMD-UNIT,jdownloader.service,PROXY
  - SYSTEMD-UNIT,backup.service,DIRECT
```

The unit is the nearest component of the owner's cgroup path named like a
service or scope: the cgroup itself or its closest such ancestor. Slices are
skipped, and cgroups below a unit's own, such as a container's
`libpod-payload-…` or `runtime`, belong to that unit. If that name isn't a valid
unit name, the unit is unknown and no component further up is tried. Names are
compared exactly, as systemd spells them, including escapes such as `\x2d`. The
payload must be a full service or scope name; a template without an instance,
a slice or another unit type is rejected when the configuration loads.
Connections show the unit in `systemdUnit` in the connection list.

A rootless Podman container's connections leave the host through its pasta
process, so they are owned by pasta. How the container is started decides
which unit that pasta runs in:

| Started as | pasta | Unit |
|---|---|---|
| Quadlet `NAME.container` | one per container | `NAME.service` (pasta in its `runtime` cgroup) |
| `systemd-run --user --unit=NAME podman run …` | one per container | `NAME.service` |
| `podman run` from a shell | one per container | `podman-<PID>.scope`, not named after the container |
| Quadlet `NAME.pod` | one per pod, shared by its containers | `NAME-pod.service` |
| `podman pod create` from a shell | one per pod, shared by its containers | `podman-<PID>.scope` |
| `--network` naming a user-defined network | one shared by all such containers | `rootless-netns-<ID>.scope` |

So a Quadlet container is routed by its service name, and the containers of a
Quadlet pod together by the pod's service. Containers on a
user-defined network share one pasta, and they can't be told apart this way.
`SYSTEMD-UNIT` identifies any cooperative unit, not only containers.

With `-exec-paths`, the loader also records the path of each cgroup its hooks
see (feature bit 1, the `cgroup_paths` map), and mihomo names cgroups from it
alone: it needs no access to cgroupfs, and a scope that has ended is still
named. An ID missing there stays unknown.

A loader without `-exec-paths` records IDs only. mihomo then resolves an ID by
listing `/sys/fs/cgroup`, whose directory inode numbers are the IDs, so it needs
to see the host's cgroupfs, outside any private cgroup namespace (the hardened
service binds it read-only in `/proc` mode). It keeps the paths it found and
lists the tree again for an ID it doesn't know: straight away for an ID newer
than all known ones, at most once a second otherwise. A scope removed before it
was ever seen can't be named, and the connection then has no app.

The owner's cgroup record is only used when it belongs to the owner record of
the same connection, since the maps are evicted independently.

With a loader that predates owner cgroups, or without `-exec-paths` and a
cgroupfs mihomo can't list, nothing is attributed and `FLATPAK-APP` and `SYSTEMD-UNIT` never match; once such a rule is
configured, the missing map is logged once per loader start:

```text
[Process] Can't attribute connections to cgroups, so FLATPAK-APP and SYSTEMD-UNIT rules match nothing: the socketowner loader doesn't publish owner cgroups (update it)
```

and a cgroupfs that can't be listed once per distinct error:

```text
[Process] Can't read cgroup names from /sys/fs/cgroup: permission denied
```

A cgroup name is attribution for cooperative apps, not a security boundary.
Any process can start a scope with any name through its systemd user manager
(`systemd-run --user --scope --unit=app-flatpak-…`) or move itself within the
cgroups delegated to it, just as it can choose its process name. A unit name can be
chosen the same way. The cgroup lookup is kept separate from the rules, in
`process.FindCgroup`, which both rules use.

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
  "cgroups": {
    "available": true,
    "mapOpen": true,
    "pathsMapOpen": true,
    "source": "bpf"
  },
  "counters": {
    "bpfHits": 21,
    "bpfMisses": 3,
    "procFallbacks": 2,
    "wineKnown": 5,
    "wineUnknown": 1,
    "wineStaleRefused": 0,
    "cgroupKnown": 4,
    "cgroupUnknown": 17
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
  "cgroups": {
    "available": false,
    "mapOpen": false,
    "pathsMapOpen": false,
    "source": "cgroupfs",
    "root": "/sys/fs/cgroup",
    "rootError": "permission denied"
  },
  "counters": {
    "bpfHits": 0,
    "bpfMisses": 0,
    "procFallbacks": 0,
    "wineKnown": 0,
    "wineUnknown": 0,
    "wineStaleRefused": 0,
    "cgroupKnown": 0,
    "cgroupUnknown": 0
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
- `cgroups.available` is true while connections can be attributed to cgroups
  for `FLATPAK-APP`. `cgroups.mapOpen` says the loader's owner-cgroup map is
  open and `cgroups.pathsMapOpen` its cgroup paths; `cgroups.mapError` says why
  they aren't while the socket-owner map is, such as a loader that doesn't
  publish them. `cgroups.source` is `bpf` when names come from those paths and
  `cgroupfs` otherwise; then the last listing of `cgroups.root` must have
  succeeded, finding `cgroups.knownCgroups` cgroups, or `cgroups.rootError` says
  why it didn't. Answering lists the cgroupfs once if no lookup has yet.
- The counters grow from process start and are never reset. `bpfHits` and
  `bpfMisses` count the lookups that consulted the maps; `procFallbacks` counts
  the ones that went through netlink and the `/proc` search instead, which never
  happens with `bpfOnly`. `wineKnown` and `wineUnknown` count the Wine records
  found, by whether the Windows program could be established. `cgroupKnown` and
  `cgroupUnknown` count cgroup lookups by whether they named a cgroup.

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

`-test.run Cgroup` covers owner cgroups. Its scope test starts processes in
transient scopes of a user's systemd manager, named like Flatpak's, and checks
that they are attributed, that a process outside them and a scope whose name
isn't a valid app ID are not, and that a removed scope is still named with
`-exec-paths` and unknown without. It needs a
user with a running systemd user manager; with an installed Flatpak app that
has `python3`, a second test checks a real `flatpak run`. With an image that
has busybox `nc` and that the user has pulled, a third test starts a rootless
Quadlet container from `$XDG_RUNTIME_DIR/containers/systemd`, which connects to
a host listener, and checks that the host socket belongs to its pasta and to the
container's service:

```sh
sudo env SOCKOWNER_MAP=/sys/fs/bpf/mihomo/maps/conn_owners \
    SOCKOWNER_SCOPE_USER=<user> SOCKOWNER_FLATPAK_APP=org.flatpak.Builder \
    SOCKOWNER_PODMAN_IMAGE=docker.io/library/alpine:latest \
    ./bin/process.test -test.v -test.run Cgroup
```

A dedicated loader `-pin` directory can be used with the corresponding
`SOCKOWNER_MAP`. Stop the test loader afterwards with the same `-pin` and `detach`.
