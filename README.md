# Mihomo with Linux process attribution

This build of [Mihomo](https://github.com/MetaCubeX/mihomo) adds:

- Linux process lookup through socketowner's BPF maps, so `PROCESS-NAME` and
  `PROCESS-PATH` rules work without giving mihomo permission to inspect other
  processes.
- `WINE-PROCESS-NAME` and `WINE-PROCESS-PATH` rules for the Windows program
  behind a Wine connection, including one relayed by a sandbox's pasta.
  Programs whose full path is unavailable can match by name.
- `FLATPAK-APP` rules for the Flatpak app that owns a connection, and
  `SYSTEMD-UNIT` rules for its systemd service or scope, which also routes a
  rootless Podman container started as a Quadlet.
- `GET /process-lookup` on the external controller, which reports whether
  process lookup is working and where its answers come from.
- Nameservers for direct outbounds, queried through the outbound itself, with
  the answering server shown in the connection list.

Connection statistics and TLS hostname discovery stay on their own branches and
are not part of `main`.

## Install on openSUSE Tumbleweed

The [home:Nosini:proxy](https://build.opensuse.org/project/show/home:Nosini:proxy)
repository on the openSUSE Build Service builds this mihomo from `main`, together
with socketowner and hardened-proxy-service. Add it with a higher priority than the
distribution's repositories, since its `mihomo` replaces openSUSE's:

```sh
sudo zypper ar -p 90 -f https://download.opensuse.org/repositories/home:/Nosini:/proxy/openSUSE_Tumbleweed/ nosini-proxy
sudo zypper ref nosini-proxy
sudo zypper in mihomo
```

The `mihomo` package installs only the executable, `/usr/bin/mihomo`, without a
service or configuration. It is built without the EasyTier outbound, whose core
upstream ships prebuilt. For the sandboxed service with its kill switch and
process lookup, install `hardened-proxy-service` instead, which pulls in `mihomo`
and recommends `socketowner`; add `hardened-proxy-service-wine-observer` for Wine
names. None of its services are enabled on installation; its
[README](https://github.com/nosini/hardened-proxy-service) covers the
configuration and enabling them.

## Build from source

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

This build disables the hub's core self-update (`POST /upgrade`), which would
replace it with a stock MetaCubeX binary. Geo database updates are unchanged.

Install the privileged [socketowner](https://github.com/nosini/socketowner)
loader separately. For Wine names, also install its Wine observer and run it
before launching games.
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service)
provides systemd units, map permissions and SELinux policy. Its Wine observer
unit is optional and must be enabled separately.

See [process lookup configuration](docs/socketowner.md) for the map settings,
fallback behavior, rule details and integration tests. For example, with the
loader installed and, for the Wine rule, the observer running:

```yaml
rules:
  - WINE-PROCESS-NAME,example.exe,REJECT
  - FLATPAK-APP,org.example.App,PROXY
  - SYSTEMD-UNIT,backup.service,DIRECT
```

`FLATPAK-APP` and `SYSTEMD-UNIT` need a socketowner loader that records owner
cgroups. The same documentation explains how rootless Podman containers map to
systemd units.

Process, Wine, Flatpak and unit attribution support cooperative applications; they
are not a security boundary against a program forging its own identity. Review
unknown-flow and DNS behavior in the
[Wine observer documentation](https://github.com/nosini/socketowner/tree/main/wine)
before adding a blanket `wine-unknown` rejection.

## Nameservers for direct outbounds

A `type: direct` outbound can send its own DNS queries through itself. With
`nameserver` set, lookups for its connections use those servers and
leave with the outbound's `interface-name` and `routing-mark`, so a DNS server
that chooses its upstream by client address sees the same source as the
traffic. Each outbound keeps its own cache.

```yaml
proxies:
  - name: exit-a
    type: direct
    interface-name: eth0.110
    nameserver: [udp://10.0.0.53]
```

See [nameservers for direct outbounds](docs/direct-nameserver.md) for the
accepted entries and the exact behavior.

## Development and license

Upstream is an unmodified, pinned Git submodule under `upstream/mihomo`.
Our integration patches and source additions live on `main`; `build/mihomo`
is generated. See [development](docs/development.md) for editing, testing and
upstream updates. Upstream documentation remains available in the submodule.

The source retains Mihomo's [GPL-3.0 license](LICENSE).
