# Development

The root repository owns the process-attribution additions, their documentation,
integration patches and build commands. `upstream/mihomo` is the unmodified
MetaCubeX repository, pinned to `94b13aed49b8dc41973e4bb3f721c5fa2c5c5c1f`.
The initial pin preserves the upstream revision used by the tested Wine build;
this layout change does not upgrade upstream or add other experimental features.

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
source paths require review. Dirty tracked files in the submodule are rejected;
untracked files are not copied. Source archives with Git metadata removed can
also be assembled. The upstream submodule is never patched in place.

Edit additions in `src/`. To change an integration patch, edit the relevant file
in a prepared `build/mihomo`, compare it against the pinned upstream file and
update the patch. Running `make prepare` again replaces edits in the assembly.
Our internal Go tests live beside their package sources in `src/` and are copied
to the same package directories as upstream.

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
outer repository and can be overridden with `VERSION=` and `BUILDTIME=`. Build
output defaults to the outer `bin/` and can be overridden with `BINDIR=`.
Choose a Go toolchain through `PATH` for upstream build targets; `GO=` also
selects the executable used by this Makefile's Go test commands.

## Update upstream

Choose a specific upstream Alpha commit, then:

```sh
git -C upstream/mihomo fetch origin Alpha
git -C upstream/mihomo checkout --detach COMMIT
make prepare
make test
make linux-amd64
git add upstream/mihomo patches src docs
```

Resolve patch or overlay conflicts in this repository and repeat validation.
Review changes to upstream dependencies and build behavior as part of the
update. Record the selected revision in this document with the submodule pin.
Never commit local modifications inside the upstream submodule.

The original `connection-statistics` and `ebpf-hostname-discovery` branches are
preserved with their existing history and layout. Their features are not applied
by the `main` assembly. Existing attribution branches are also retained, so the
pre-migration source and validation history remain accessible.
