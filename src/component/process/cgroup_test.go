package process

import "testing"

func TestParseFlatpakScope(t *testing.T) {
	for name, want := range map[string]string{
		// Flatpak 1.11 and later: escaped app ID, random instance ID.
		`app-flatpak-org.jdownloader.JDownloader-1873420961.scope`: "org.jdownloader.JDownloader",
		`app-flatpak-org.example.My\x2dApp-42.scope`:               "org.example.My-App",
		`app-flatpak-org.example.Some_App2-0.scope`:                "org.example.Some_App2",
		// Earlier versions: unescaped app ID, process ID.
		`app-flatpak-org.example.My-App-12345.scope`: "org.example.My-App",
		`app-flatpak-test.App-123.scope`:             "", // two elements only
		`app-flatpak-org.example.App.scope`:          "", // no instance
		`app-flatpak-org.example.App-.scope`:         "",
		`app-flatpak-org.example.App-12a.scope`:      "",
		`app-flatpak-org.example.App-1.service`:      "",
		`app-flatpak-org.exa-mple.App-1.scope`:       "", // "-" only in the last element
		`app-flatpak-org.example.1App-1.scope`:       "", // element starts with a digit
		`app-flatpak-org..example.App-1.scope`:       "",
		`app-flatpak-org.example.App\x2f..-1.scope`:  "", // escapes decode to invalid characters
		`app-flatpak-org.example.App\x2-1.scope`:     "",
		`app-flatpak-org.example.App\-1.scope`:       "",
		`app-flatpak--1.scope`:                       "",
		`app-org.example.App-1.scope`:                "",
		`app-gnome-org.example.App-1234.scope`:       "",
	} {
		got, ok := ParseFlatpakScope(name)
		if ok != (want != "") || got != want {
			t.Errorf("%s: %q, %v, want %q", name, got, ok, want)
		}
	}
}

func TestFlatpakAppFromCgroupPath(t *testing.T) {
	const user = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
	for path, want := range map[string]string{
		user + `app-flatpak-org.jdownloader.JDownloader-1873420961.scope`: "org.jdownloader.JDownloader",
		// A child cgroup of the scope belongs to the app.
		user + `app-flatpak-org.example.App-7.scope/sub`:        "org.example.App",
		user + `app-flatpak-org.example.App-7.scope/sub/deeper`: "org.example.App",
		// Not a Flatpak scope.
		user + `app-gnome-org.gnome.Terminal-4242.scope`: "",
		user + `app-org.example.App-7.scope`:             "",
		"/system.slice/mihomo.service":                   "",
		"/":                                              "",
		"":                                               "",
		// Lookalikes: only the nearest app-flatpak-* component counts, and
		// only as a whole name.
		user + `app-flatpak-org.example.Outer-1.scope/app-flatpak-bad-2.scope`:            "",
		user + `app-flatpak-org.example.Outer-1.scope/app-flatpak-org.example.In-2.scope`: "org.example.In",
		user + `my-app-flatpak-org.example.App-7.scope`:                                   "",
		user + `app-flatpak-org.example.App-7.scope.d/x`:                                  "",
		`/app-flatpak-org.example.App-7.scope`:                                            "org.example.App",
	} {
		got, ok := FlatpakAppFromCgroupPath(path)
		if ok != (want != "") || got != want {
			t.Errorf("%s: %q, %v, want %q", path, got, ok, want)
		}
	}
}

func TestValidFlatpakAppID(t *testing.T) {
	long := "org.example."
	for len(long) < 256 {
		long += "a"
	}
	for id, want := range map[string]bool{
		"org.jdownloader.JDownloader": true,
		"org.example.App-Name":        true,
		"_org.example._1":             true,
		"org.example":                 false,
		"org.example.":                false,
		".org.example.App":            false,
		"org.ex-ample.App":            false,
		"org.example.9App":            false,
		"org.example.App/..":          false,
		"org.example.Äpp":             false,
		long[:255]:                    true,
		long:                          false,
	} {
		if got := ValidFlatpakAppID(id); got != want {
			t.Errorf("%q: %v, want %v", id, got, want)
		}
	}
}

func TestSystemdUnitFromCgroupPath(t *testing.T) {
	const user = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
	const payload = "libpod-payload-8f7d2ed094aa54027a99d0d9c61b63a126b9cface581f34e65c2fff3152ed135"
	for path, want := range map[string]string{
		// A Quadlet container: its payload, and the pasta, conmon and
		// fuse-overlayfs in runtime, belong to the service.
		user + "jdownloader.service/" + payload: "jdownloader.service",
		user + "jdownloader.service/runtime":    "jdownloader.service",
		user + "jdownloader.service":            "jdownloader.service",
		// podman run outside a unit, and an ad-hoc container's payload.
		"/user.slice/user-1000.slice/user@1000.service/user.slice/podman-2494.scope":     "podman-2494.scope",
		"/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-3b6c5387.scope": "libpod-3b6c5387.scope",
		// The nearest unit wins over the user manager above it.
		user + `app-flatpak-org.example.App-7.scope/sub`:           `app-flatpak-org.example.App-7.scope`,
		"/user.slice/user-1000.slice/user@1000.service/init.scope": "init.scope",
		"/system.slice/mihomo.service":                             "mihomo.service",
		"/system.slice/system-getty.slice/getty@tty1.service":      "getty@tty1.service",
		`/system.slice/dev-disk-by\x2duuid.service`:                `dev-disk-by\x2duuid.service`,
		// Slices alone, or no unit.
		"/user.slice/user-1000.slice": "",
		"/machine.slice/x":            "",
		"/":                           "",
		"":                            "",
		// The nearest unit-like name is invalid: unknown, not the one above.
		user + "x.service/bad name.service": "",
		user + "x.service/@i.service":       "",
		// A drop-in-like name is not a unit; the user manager above is.
		user + "x.service.d/sub": "user@1000.service",
	} {
		got, ok := SystemdUnitFromCgroupPath(path)
		if ok != (want != "") || got != want {
			t.Errorf("%s: %q, %v, want %q", path, got, ok, want)
		}
	}
}

func TestValidSystemdUnitName(t *testing.T) {
	long := make([]byte, 247) // 255 characters with ".service"
	for i := range long {
		long[i] = 'a'
	}
	for name, want := range map[string]bool{
		"jdownloader.service":       true,
		"podman-2494.scope":         true,
		"getty@tty1.service":        true,
		`dev-disk-by\x2duuid.scope`: true,
		"a:b_c.d.service":           true,
		string(long) + ".service":   true,
		string(long) + "a.service":  false,
		"jdownloader":               false,
		"user.slice":                false,
		"sockets.target":            false,
		".service":                  false,
		"getty@.service":            false,
		"a@b@c.service":             false,
		"@x.service":                false,
		"has space.service":         false,
		"a/b.service":               false,
		"*.service":                 false,
		"jdownloader.SERVICE":       false,
	} {
		if got := ValidSystemdUnitName(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}
