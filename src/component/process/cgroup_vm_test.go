//go:build linux && sockowner_vm

package process

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireCgroupMap skips unless the loader publishes owner cgroups.
func requireCgroupMap(t *testing.T) {
	requireMap(t)
	sockOwners.mu.RLock()
	open := sockOwners.cgroupsFd >= 0
	reason := sockOwners.cgroupErr
	sockOwners.mu.RUnlock()
	if !open {
		t.Skip("owner-cgroup map not available: " + reason)
	}
}

// userSession returns the command prefix that runs a command as the user
// named in SOCKOWNER_SCOPE_USER, talking to that user's systemd manager.
func userSession(t *testing.T) []string {
	name := os.Getenv("SOCKOWNER_SCOPE_USER")
	if name == "" {
		t.Skip("set SOCKOWNER_SCOPE_USER to a user with a running systemd user manager")
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	runtime := "/run/user/" + u.Uid
	if _, err := os.Stat(filepath.Join(runtime, "systemd", "private")); err != nil {
		t.Skipf("no systemd user manager for %s: %v", name, err)
	}
	return []string{"runuser", "-u", name, "--", "env", "XDG_RUNTIME_DIR=" + runtime,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus"}
}

// sharedChildBinary copies the test binary where another user can run it.
func sharedChildBinary(t *testing.T) string {
	dir, err := os.MkdirTemp("", "cgroup-vm-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "sockowner-child")
	if err := os.WriteFile(child, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return child
}

// connectFrom runs argv, which must connect to the returned listener, and
// returns the accepted connection's source and a function that ends the
// command.
func connectFrom(t *testing.T, l net.Listener, argv []string) (netip.AddrPort, func()) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	var c net.Conn
	select {
	case c = <-accepted:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("%v didn't connect: %s", argv, stderr.String())
	}
	src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	return src, func() {
		c.Close()
		stdin.Close()
		cmd.Wait()
	}
}

func findApp(t *testing.T, src netip.AddrPort) (path, app string) {
	t.Helper()
	path, ok := FindCgroup("tcp", src.Addr(), int(src.Port()))
	if !ok {
		return "", ""
	}
	app, _ = FlatpakAppFromCgroupPath(path)
	return path, app
}

// A process that systemd-run started in a scope named like Flatpak's is
// attributed to that app; one outside it isn't, nor is one in a scope whose
// name isn't a valid app ID. Once the scope is gone, a lookup that has to
// walk cgroupfs again can't name it.
func TestCgroupFlatpakScope(t *testing.T) {
	requireCgroupMap(t)
	prefix := userSession(t)
	child := sharedChildBinary(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	childArgv := []string{"env", childEnv + "=tcp", "SOCKOWNER_ADDR=" + addr, child}
	scoped := func(unit string) []string {
		argv := append([]string{}, prefix...)
		argv = append(argv, "systemd-run", "--user", "--scope", "--quiet", "--unit="+unit, "--")
		return append(argv, childArgv...)
	}
	instance := os.Getpid()

	unit := fmt.Sprintf(`app-flatpak-org.example.Test\x2dApp-%d.scope`, instance)
	src, stop := connectFrom(t, l, scoped(unit))
	path, app := findApp(t, src)
	t.Logf("in scope: %s -> %q", path, app)
	if !strings.HasSuffix(path, "/app.slice/"+unit) || app != "org.example.Test-App" {
		stop()
		t.Fatalf("in scope: cgroup %q, app %q", path, app)
	}
	stop()

	src, stop = connectFrom(t, l, append(append([]string{}, prefix...), childArgv...))
	path, app = findApp(t, src)
	stop()
	t.Logf("outside: %s -> %q", path, app)
	if path == "" || app != "" {
		t.Fatalf("outside a scope: cgroup %q, app %q", path, app)
	}

	unit = fmt.Sprintf("app-flatpak-test.App-%d.scope", instance)
	src, stop = connectFrom(t, l, scoped(unit))
	path, app = findApp(t, src)
	stop()
	t.Logf("invalid app ID: %s -> %q", path, app)
	if !strings.HasSuffix(path, "/"+unit) || app != "" {
		t.Fatalf("invalid app ID: cgroup %q, app %q", path, app)
	}

	// The scope ends with its process. Forget the walk that found it.
	unit = fmt.Sprintf("app-flatpak-org.example.Gone-%d.scope", instance)
	src, stop = connectFrom(t, l, scoped(unit))
	stop()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, _ := exec.Command("sh", "-c", "find /sys/fs/cgroup/user.slice -maxdepth 6 -name '"+unit+"'").Output()
		if len(strings.TrimSpace(string(out))) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scope %s not removed", unit)
		}
		time.Sleep(100 * time.Millisecond)
	}
	cgroupPaths.mu.Lock()
	cgroupPaths.byID, cgroupPaths.walkedAt = nil, time.Time{}
	cgroupPaths.mu.Unlock()
	if path, app := findApp(t, src); path != "" || app != "" {
		t.Fatalf("removed scope: cgroup %q, app %q", path, app)
	}
	if _, ok := lookupSockCgroup("tcp", src.Addr(), int(src.Port())); !ok {
		t.Fatal("the cgroup ID itself should still be recorded")
	}
}

// With SOCKOWNER_FLATPAK_APP naming an installed app that has python3, a
// connection from flatpak run is attributed to it.
func TestCgroupFlatpakRun(t *testing.T) {
	requireCgroupMap(t)
	app := os.Getenv("SOCKOWNER_FLATPAK_APP")
	if app == "" {
		t.Skip("set SOCKOWNER_FLATPAK_APP to an installed Flatpak app with python3")
	}
	prefix := userSession(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	script := fmt.Sprintf("import socket,sys; s=socket.create_connection(('127.0.0.1',%d)); sys.stdin.read()", port)
	argv := append(append([]string{}, prefix...), "flatpak", "run", "--command=python3", app, "-c", script)
	src, stop := connectFrom(t, l, argv)
	defer stop()
	path, got := findApp(t, src)
	t.Logf("flatpak run %s: %s -> %q", app, path, got)
	if got != app {
		t.Fatalf("flatpak run %s: cgroup %q, app %q", app, path, got)
	}
}

// The health snapshot reports cgroup attribution as available.
func TestCgroupHealth(t *testing.T) {
	requireCgroupMap(t)
	h := LookupHealth().Cgroups
	if !h.Available || !h.MapOpen || h.KnownCgroups == 0 || h.RootError != "" {
		t.Fatalf("%+v", h)
	}
}
