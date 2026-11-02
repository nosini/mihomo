# Mihomo with Linux process attribution

This build of [Mihomo](https://github.com/MetaCubeX/mihomo) adds Linux process
lookup through socketowner's BPF maps and identifies Windows programs behind
Wine connections, including sandboxes using pasta. It supports `PROCESS-NAME`
and `PROCESS-PATH` rules without giving mihomo permission to inspect other
processes. Wine clients whose full path is unavailable can match by name.

Connection statistics and TLS hostname discovery remain on their separate
experimental branches and are excluded from `main`.

## Build and install

Install Git, Python 3, make and a Go toolchain supported by the pinned upstream
source. The current source has been built and tested with Go 1.27.3.

```sh
git clone --recurse-submodules https://github.com/nosini/mihomo.git
cd mihomo
make linux-amd64
sudo install -m 755 bin/mihomo-linux-amd64 /usr/local/bin/mihomo
sudo restorecon -v /usr/local/bin/mihomo
sudo systemctl restart mihomo.service
```

`linux-amd64` requires an x86-64-v3 CPU, following upstream's Makefile. Use
`make linux-amd64-v1` for the baseline x86-64 target. Other upstream Makefile
build targets are available through this repository's Makefile as well.
For an existing checkout, initialize the pinned source with
`git submodule update --init --recursive` before building.

Install the privileged [socketowner](https://github.com/nosini/socketowner)
loader separately. For Wine names, also install its Wine observer and run it
before launching games.
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service)
provides systemd units, map permissions and SELinux policy. Its Wine observer
unit is optional and must be enabled separately.

See [process lookup configuration](docs/socketowner.md) for the map settings,
fallback behavior and integration tests. For example, once the observer is
installed and running:

```yaml
rules:
  - PROCESS-NAME,example.exe,REJECT
```

Native socketowner and Wine attribution support cooperative applications; they
are not a security boundary against a program forging its own identity. Review
unknown-flow and DNS behavior in the
[Wine observer documentation](https://github.com/nosini/socketowner/tree/main/wine)
before adding a blanket `wine-unknown` rejection.

## Development and license

Upstream is an unmodified, pinned Git submodule under `upstream/mihomo`.
Our integration patches and source additions live on `main`; `build/mihomo`
is generated. See [development](docs/development.md) for editing, testing and
upstream updates. Upstream documentation remains available in the submodule.

The source retains Mihomo's [GPL-3.0 license](LICENSE).
