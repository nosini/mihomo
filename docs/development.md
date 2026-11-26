# Development

The root repository owns the process-attribution additions, their documentation,
integration patches and build commands. `upstream/mihomo` is the unmodified
MetaCubeX repository, pinned to upstream Alpha commit
`3c0d10a503f7b2fde3fe167d4d91dd05725d5268`.

## Source layout

```text
upstream/mihomo/     Pinned, unmodified upstream source
src/                Added Go source and tests, using upstream-relative paths
patches/            Changes to existing upstream files, applied in filename order
docs/               Our documentation
scripts/            Source assembly
tests/              Assembly regression tests
build/mihomo/       Generated complete source tree
bin/                Build output (including the privileged-test executable)
```

`make prepare` copies committed upstream files into a fresh temporary directory,
applies the patches and adds `src/` and `docs/`. It replaces `build/mihomo` only
after assembly succeeds. Patch failures and files added upstream at one of our
source paths require review. Dirty tracked files in the submodule are rejected,
as is a submodule checkout other than the commit staged in the outer repository;
untracked upstream files are not copied. When the outer checkout has Git
metadata, only tracked files under `src/`, `docs/` and `patches/` are assembled,
using their working-tree content. Untracked, ignored and editor backup files are
left out. Source archives with Git metadata removed can also be assembled; they
copy the files that are present, skipping `__pycache__`, `*.pyc`, `*~` and
`.*.swp`. The upstream submodule is never patched in place.

Assembly records a hash of the upstream revision, patch contents, overlaid files
and this script in `build/.mihomo.stamp`. If `build/mihomo` exists and that
stamp still matches, `make prepare` skips assembly;
`python3 scripts/prepare-source.py --force` always reassembles. The upstream
dirty-tree and pin checks still run before deciding to skip.

Edit additions in `src/`. To change an integration patch, edit the relevant file
in a prepared `build/mihomo`, compare it against the pinned upstream file and
update the patch. Running `make prepare` replaces the assembly when its inputs
change; use `--force` to discard edits made only in `build/mihomo`. Our internal
Go tests live beside their package sources in `src/` and are copied to the same
package directories as upstream.

## Build and test

```sh
git submodule update --init --recursive
make test-assembly
make test-process
make linux-amd64
```

`make test` runs assembly regression tests and the full upstream/local Go suite
with the upstream inbound interop fixture disabled. Some other upstream tests
may need networking. `make test-process` runs the unprivileged attribution tests.
`make test-vm` compiles `bin/process.test` with the `sockowner_vm` tag; run it only
on a disposable machine with the separately installed loader, as described in
[socket-owner integration tests](socketowner.md#integration-tests).

Build commands delegate to upstream's Makefile, preserving its build tags,
architecture choices and linker flags. Version and build time come from the
outer repository when it is a Git checkout, marked `-dirty` when its tracked
tree or upstream pin differs from the commit. An archive without Git metadata,
or a checkout inside an unrelated enclosing repository, reports the version as
`unknown`. Both values can be overridden with `VERSION=` and `BUILDTIME=`. Build
output defaults to the outer `bin/` and can be overridden with `BINDIR=`.
`GO=` selects the Go toolchain for both tests and upstream build targets.
`make clean` removes only `build/`, leaving binaries in `bin/`.

## Update upstream

Choose a specific upstream Alpha commit, then:

```sh
git -C upstream/mihomo fetch origin Alpha
git -C upstream/mihomo checkout --detach COMMIT
git add upstream/mihomo
make prepare
make test
make linux-amd64
git add patches src docs
```

Assembly refuses a submodule checkout which differs from the staged pin, so stage
the new pin before preparing it.

Resolve patch or overlay conflicts in this repository and repeat validation.
Review changes to upstream dependencies and build behavior as part of the
update. Record the selected revision in this document with the submodule pin.
Never commit local modifications inside the upstream submodule.

Connection statistics and TLS hostname discovery are maintained on their
respective feature branches. Process and Wine attribution and nameservers for
direct outbounds are part of `main`; the latter is
`patches/0002-direct-outbound-nameserver.patch` with
`src/adapter/outbound/direct_nameserver*.go`, and the verifiable DNS
metadata those outbounds record is
`patches/0004-direct-nameserver-metadata.patch` with `src/dns/query_trace*.go`.
`FLATPAK-APP` rules and the cgroup fields of connection metadata are
`patches/0005-flatpak-app-rule.patch` with `src/component/process/cgroup*.go`
and `src/rules/common/flatpak_app.go`. `SYSTEMD-UNIT` rules and the
`systemdUnit` metadata field are `patches/0006-systemd-unit-rule.patch` with
`src/rules/common/systemd_unit.go`; they reuse that cgroup lookup. The
destination keys that tell apart sockets sharing a source port are
`patches/0007-flow-destination.patch` with `src/component/process/flowkey*.go`
and `src/constant/flowpeers_test.go`, and UDP sessions that are replaced when
another process sends from their address and port are
`patches/0008-udp-session-owner.patch` with `src/tunnel/udpsession*.go` and
`src/component/process/flowowner.go`.

## Releases

The openSUSE packages in
[home:Nosini:proxy](https://build.opensuse.org/project/show/home:Nosini:proxy) build
release tags. A tag is named `vUPSTREAM-N`: the upstream release the pinned submodule
builds on, and the fork's release number on it, starting at 1 for each upstream
release. `v1.19.34-1` becomes package version `1.19.34.1`. Other `v*` tags, such as
the upstream tags in this repository's history, are not releases. Tag a commit on
`main` and push the tag:

```sh
git tag -s v1.19.34-2 -m 'mihomo 1.19.34-2'
git push github v1.19.34-2
```

`.github/workflows/obs.yml` then sets the tag as the revision of the package's
`_service` on src.opensuse.org, which OBS builds. It needs the `OBS_GIT_TOKEN` secret,
a src.opensuse.org access token that can write to `Nosini/mihomo`.
