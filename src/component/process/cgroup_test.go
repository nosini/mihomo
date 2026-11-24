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
		user + `app-flatpak-org.example.Outer-1.scope/app-flatpak-bad-2.scope`:       "",
		user + `app-flatpak-org.example.Outer-1.scope/app-flatpak-org.example.In-2.scope`: "org.example.In",
		user + `my-app-flatpak-org.example.App-7.scope`:                              "",
		user + `app-flatpak-org.example.App-7.scope.d/x`:                             "",
		`/app-flatpak-org.example.App-7.scope`:                                       "org.example.App",
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
