//go:build linux && sockowner_vm

// Compares the BPF socket-owner lookup with the netlink and /proc lookup on a
// machine where the socket-owner programs are attached. Build with
// "go test -c -tags sockowner_vm" and run as root.

package process

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const childEnv = "SOCKOWNER_CHILD"

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		runChild(mode, os.Getenv("SOCKOWNER_ADDR"))
		os.Exit(0)
	}
	if path := os.Getenv("SOCKOWNER_MAP"); path != "" {
		SetSockOwnerMap(path)
	}
	os.Exit(m.Run())
}

// runChild prints its PID, then talks to addr according to mode and waits for
// stdin to close unless it is meant to exit straight away.
func runChild(mode, addr string) {
	fmt.Println(os.Getpid())
	switch mode {
	case "tcp":
		c, err := net.Dial("tcp", addr)
		if err != nil {
			os.Exit(1)
		}
		defer c.Close()
	case "inherited":
		ap := netip.MustParseAddrPort(addr)
		sa := &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
		if err := syscall.Connect(3, sa); err != nil {
			os.Exit(1)
		}
	case "inherited-write":
		// Sends on a connected socket, which skips the sendmsg hooks.
		if _, err := syscall.Write(3, []byte("x")); err != nil {
			os.Exit(1)
		}
	case "udp-reconnect":
		// Disconnecting an autobound UDP socket releases its port, so
		// the second datagram leaves from a new one.
		ap := netip.MustParseAddrPort(addr)
		sa := &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			os.Exit(1)
		}
		var unspec [16]byte // struct sockaddr with sa_family AF_UNSPEC
		if syscall.Connect(fd, sa) != nil {
			os.Exit(1)
		}
		syscall.Write(fd, []byte("1"))
		if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&unspec)), uintptr(len(unspec))); errno != 0 {
			os.Exit(1)
		}
		if syscall.Connect(fd, sa) != nil {
			os.Exit(1)
		}
		syscall.Write(fd, []byte("2"))
	case "udp-twice":
		// Sends once, and again after a line on stdin.
		c, err := net.Dial("udp", addr)
		if err != nil {
			os.Exit(1)
		}
		defer c.Close()
		c.Write([]byte("1"))
		bufio.NewReader(os.Stdin).ReadString('\n')
		c.Write([]byte("2"))
	case "udp-closed", "udp-exit":
		c, err := net.Dial("udp", addr)
		if err != nil {
			os.Exit(1)
		}
		c.Write([]byte("x"))
		c.Close()
		if mode == "udp-exit" {
			return
		}
	}
	io.Copy(io.Discard, os.Stdin)
}

type lookupResult struct {
	path string
	err  error
	took time.Duration
}

func lookupBPF(network string, ap netip.AddrPort) lookupResult {
	start := time.Now()
	owner, ok := lookupSockOwner(network, ap.Addr(), int(ap.Port()))
	if !ok {
		return lookupResult{err: ErrNotFound, took: time.Since(start)}
	}
	path, err := resolveSockOwnerPath(owner)
	if err != nil {
		err = fmt.Errorf("%w (pid %d)", err, owner.Tgid)
	}
	return lookupResult{path: path, err: err, took: time.Since(start)}
}

func lookupLegacy(network string, ap netip.AddrPort) lookupResult {
	start := time.Now()
	uid, inode, err := resolveSocketByNetlink(network, ap.Addr(), int(ap.Port()))
	if err != nil {
		return lookupResult{err: err, took: time.Since(start)}
	}
	path, err := resolveProcessNameByProcSearch(inode, uid)
	return lookupResult{path: path, err: err, took: time.Since(start)}
}

type tally struct {
	hits   map[string]int
	errors map[string]int
	total  time.Duration
	n      int
}

func (t *tally) add(r lookupResult) {
	if t.hits == nil {
		t.hits, t.errors = map[string]int{}, map[string]int{}
	}
	if r.err != nil {
		t.errors[r.err.Error()]++
	} else {
		t.hits[filepath.Base(r.path)]++
	}
	t.total += r.took
	t.n++
}

// expectChild fails the test unless every lookup named the child.
func (t *tally) expectChild(tb testing.TB) {
	tb.Helper()
	if t.hits["sockowner-child"] != t.n {
		tb.Errorf("child named in %d of %d lookups", t.hits["sockowner-child"], t.n)
	}
}

func (t *tally) String() string {
	return fmt.Sprintf("found %v, failed %v, mean %v", t.hits, t.errors, t.total/time.Duration(t.n))
}

const rounds = 50

func childBinary(t *testing.T) string {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(t.TempDir(), "sockowner-child")
	if err := os.WriteFile(child, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return child
}

func startChild(t *testing.T, child, mode, addr string, extra *os.File) (*exec.Cmd, io.WriteCloser, int) {
	cmd := exec.Command(child)
	cmd.Env = append(os.Environ(), childEnv+"="+mode, "SOCKOWNER_ADDR="+addr)
	if extra != nil {
		cmd.ExtraFiles = []*os.File{extra}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	pid, _ := strconv.Atoi(line[:len(line)-1])
	return cmd, stdin, pid
}

func requireMap(t *testing.T) {
	if !sockOwners.lookup(func(int, uint64) bool { return true }) {
		t.Skip("socket-owner map not available at " + SockOwnerMap())
	}
}

func TestSockOwnerTCP(t *testing.T) {
	requireMap(t)
	child := childBinary(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var bpf, legacy tally
	for i := 0; i < rounds; i++ {
		cmd, stdin, _ := startChild(t, child, "tcp", l.Addr().String(), nil)
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		bpf.add(lookupBPF("tcp", src))
		legacy.add(lookupLegacy("tcp", src))
		c.Close()
		stdin.Close()
		cmd.Wait()
	}
	t.Logf("bpf:    %v", &bpf)
	t.Logf("legacy: %v", &legacy)
	bpf.expectChild(t)
}

func testUDP(t *testing.T, mode string) {
	requireMap(t)
	child := childBinary(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var bpf, legacy tally
	buf := make([]byte, 16)
	for i := 0; i < rounds; i++ {
		cmd, stdin, _ := startChild(t, child, mode, pc.LocalAddr().String(), nil)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "udp-exit" {
			cmd.Wait()
		}
		src := from.(*net.UDPAddr).AddrPort()
		bpf.add(lookupBPF("udp", src))
		legacy.add(lookupLegacy("udp", src))
		stdin.Close()
		cmd.Wait()
	}
	t.Logf("bpf:    %v", &bpf)
	t.Logf("legacy: %v", &legacy)
	sockOwners.mu.RLock()
	execMaps := sockOwners.tasksFd >= 0
	sockOwners.mu.RUnlock()
	// Without the exec-path maps, an owner that has exited can't be named.
	if mode != "udp-exit" || execMaps {
		bpf.expectChild(t)
	}
}

// The child sends one datagram from a socket it closes straight away but keeps
// running, like a resolver that has its answer.
func TestSockOwnerUDPSocketClosed(t *testing.T) { testUDP(t, "udp-closed") }

// The child exits after sending one datagram.
func TestSockOwnerUDPProcessExited(t *testing.T) { testUDP(t, "udp-exit") }

// The test process creates the socket and keeps it open; the child inherits it
// and connects.
func TestSockOwnerInherited(t *testing.T) {
	requireMap(t)
	child := childBinary(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var bpf, legacy tally
	for i := 0; i < rounds; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "socket")
		cmd, stdin, _ := startChild(t, child, "inherited", l.Addr().String(), f)
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		bpf.add(lookupBPF("tcp", src))
		legacy.add(lookupLegacy("tcp", src))
		c.Close()
		stdin.Close()
		cmd.Wait()
		f.Close()
	}
	t.Logf("bpf:    %v (test binary is %s)", &bpf, filepath.Base(os.Args[0]))
	t.Logf("legacy: %v", &legacy)
	bpf.expectChild(t)
}

// The test process connects a UDP socket and passes it to the child, which
// sends on it with write() while the test process stays alive. The datagram
// belongs to the child.
func TestSockOwnerPassedConnected(t *testing.T) {
	requireExecMaps(t) // record_send is attached with -exec-paths
	child := childBinary(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	buf := make([]byte, 16)
	var bpf tally
	for i := 0; i < rounds; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "socket")
		cmd, stdin, _ := startChild(t, child, "inherited-write", ap.String(), f)
		f.Close()
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		bpf.add(lookupBPF("udp", from.(*net.UDPAddr).AddrPort()))
		stdin.Close()
		cmd.Wait()
	}
	t.Logf("bpf: %v (test binary is %s)", &bpf, filepath.Base(os.Args[0]))
	bpf.expectChild(t)
}

func bpfCall(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

func pinObject(fd int, path string) error {
	p, _ := unix.BytePtrFromString(path)
	attr := struct {
		Pathname uint64
		BpfFd    uint32
		Flags    uint32
	}{Pathname: uint64(uintptr(unsafe.Pointer(p))), BpfFd: uint32(fd)}
	_, err := bpfCall(unix.BPF_OBJ_PIN, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func openPinnedRW(path string) (int, error) {
	p, _ := unix.BytePtrFromString(path)
	attr := struct {
		Pathname uint64
		BpfFd    uint32
		Flags    uint32
	}{Pathname: uint64(uintptr(unsafe.Pointer(p)))}
	fd, err := bpfCall(unix.BPF_OBJ_GET, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return int(fd), err
}

func mapElem(cmd uintptr, fd int, key, value unsafe.Pointer) error {
	attr := struct {
		MapFd uint32
		_     uint32
		Key   uint64
		Value uint64
		Flags uint64
	}{MapFd: uint32(fd), Key: uint64(uintptr(key)), Value: uint64(uintptr(value))}
	_, err := bpfCall(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func ownerKey(t *testing.T, network string, ap netip.AddrPort) sockOwnerKey {
	netns, err := currentNetnsCookie()
	if err != nil {
		t.Fatal(err)
	}
	key := sockOwnerKey{Netns: netns, Addr: ap.Addr().Unmap().As16(), Port: ap.Port(), Proto: unix.IPPROTO_UDP}
	if network == "tcp" {
		key.Proto = unix.IPPROTO_TCP
	}
	return key
}

// A map with bigger values must be refused: lookups copy the map's whole value
// into a sockOwnerValue.
func TestSockOwnerRejectsWrongLayout(t *testing.T) {
	attr := struct {
		Type       uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
	}{unix.BPF_MAP_TYPE_LRU_HASH, uint32(unsafe.Sizeof(sockOwnerKey{})), 2 * uint32(unsafe.Sizeof(sockOwnerValue{})), 16}
	fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		t.Skip("can't create a map: ", err)
	}
	defer unix.Close(int(fd))

	ap := netip.MustParseAddrPort("127.0.0.1:4242")
	key := ownerKey(t, "udp", ap)
	var value [2]sockOwnerValue
	value[0] = sockOwnerValue{Tgid: uint32(os.Getpid()), UID: 0, BootNs: 1}
	value[1] = sockOwnerValue{Tgid: 0xdeadbeef, UID: 0xdeadbeef, BootNs: 0xdeadbeefdeadbeef}
	if err := mapElem(unix.BPF_MAP_UPDATE_ELEM, int(fd), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("/sys/fs/bpf/mihomo-test-%d", os.Getpid())
	if err := pinObject(int(fd), pin); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pin)

	previous := SockOwnerMap()
	SetSockOwnerMap(pin)
	defer SetSockOwnerMap(previous)
	if owner, ok := lookupSockOwner("udp", ap.Addr(), int(ap.Port())); ok {
		t.Fatalf("used a map with %d-byte values: %+v", attr.ValueSize, owner)
	}
	sockOwners.mu.RLock()
	opened := sockOwners.fd >= 0
	sockOwners.mu.RUnlock()
	if opened {
		t.Fatal("kept a map with the wrong layout open")
	}
}

// A UDP socket that disconnects and connects again sends from a new port, which
// must be published too.
func TestSockOwnerUDPReconnect(t *testing.T) {
	requireMap(t)
	child := childBinary(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	buf := make([]byte, 16)
	for i := 0; i < rounds; i++ {
		cmd, stdin, _ := startChild(t, child, "udp-reconnect", pc.LocalAddr().String(), nil)
		var ports []netip.AddrPort
		for len(ports) < 2 {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			ports = append(ports, from.(*net.UDPAddr).AddrPort())
		}
		if ports[0] == ports[1] {
			t.Fatalf("source port didn't change: %v", ports[0])
		}
		r := lookupBPF("udp", ports[1])
		stdin.Close()
		cmd.Wait()
		if r.err != nil || filepath.Base(r.path) != "sockowner-child" {
			t.Fatalf("round %d: second port %v: %q, %v", i, ports[1], r.path, r.err)
		}
	}
}

// An evicted entry comes back with the socket's next packet.
func TestSockOwnerRestoresEvicted(t *testing.T) {
	requireMap(t)
	mapFd, err := openPinnedRW(SockOwnerMap())
	if err != nil {
		t.Skip("can't open the map for writing: ", err)
	}
	defer unix.Close(mapFd)
	child := childBinary(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	buf := make([]byte, 16)
	for i := 0; i < rounds; i++ {
		cmd, stdin, _ := startChild(t, child, "udp-twice", pc.LocalAddr().String(), nil)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		src := from.(*net.UDPAddr).AddrPort()
		if r := lookupBPF("udp", src); r.err != nil {
			t.Fatalf("round %d: first datagram: %v", i, r.err)
		}
		key := ownerKey(t, "udp", src)
		if err := mapElem(unix.BPF_MAP_DELETE_ELEM, mapFd, unsafe.Pointer(&key), nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := lookupSockOwner("udp", src.Addr(), int(src.Port())); ok {
			t.Fatal("entry still there after deleting it")
		}
		io.WriteString(stdin, "\n")
		if _, _, err := pc.ReadFrom(buf); err != nil {
			t.Fatal(err)
		}
		r := lookupBPF("udp", src)
		stdin.Close()
		cmd.Wait()
		if r.err != nil || filepath.Base(r.path) != "sockowner-child" {
			t.Fatalf("round %d: after eviction: %q, %v", i, r.path, r.err)
		}
	}
}

func requireExecMaps(t *testing.T) {
	requireMap(t)
	sockOwners.mu.RLock()
	defer sockOwners.mu.RUnlock()
	if sockOwners.tasksFd < 0 {
		t.Skip("exec-path maps not available next to " + SockOwnerMap())
	}
}

// With the exec-path maps, a process that has exited is still named, from
// exec_recent.
func TestExecPathOwnerExited(t *testing.T) {
	requireExecMaps(t)
	child := childBinary(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	buf := make([]byte, 16)
	for i := 0; i < rounds; i++ {
		cmd, stdin, _ := startChild(t, child, "udp-exit", pc.LocalAddr().String(), nil)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Wait()
		stdin.Close()
		r := lookupBPF("udp", from.(*net.UDPAddr).AddrPort())
		if r.err != nil || r.path != child {
			t.Fatalf("round %d: %q, %v", i, r.path, r.err)
		}
	}
}

// A record only names an owner if the process started before the owner was
// recorded; otherwise the process ID was reused.
func TestExecPathRejectsLaterProcess(t *testing.T) {
	requireExecMaps(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	owner := sockOwnerValue{Tgid: uint32(os.Getpid())}
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	owner.BootNs = uint64(ts.Nano())
	sockOwners.mu.RLock()
	path, err := sockOwners.execPathLocked(owner)
	sockOwners.mu.RUnlock()
	if err != nil || path != self {
		t.Fatalf("own process: %q, %v", path, err)
	}

	owner.BootNs = 1 // before this process started
	sockOwners.mu.RLock()
	path, err = sockOwners.execPathLocked(owner)
	sockOwners.mu.RUnlock()
	if err == nil {
		t.Fatalf("named an owner recorded before the process started: %q", path)
	}
}

// With SetSockOwnerOnly, lookups that the maps can't answer fail instead of
// searching /proc.
func TestSockOwnerOnly(t *testing.T) {
	requireExecMaps(t)
	SetSockOwnerOnly(true)
	defer SetSockOwnerOnly(false)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	src := c.LocalAddr().(*net.TCPAddr).AddrPort()
	self, _ := os.Executable()
	if _, path, err := findProcessName("tcp", src.Addr(), int(src.Port())); err != nil || path != self {
		t.Fatalf("own connection: %q, %v", path, err)
	}
	// A socket that existed before the programs were attached has no owner;
	// an unused port stands in for it.
	if _, path, err := findProcessName("tcp", src.Addr(), 1); err != ErrNotFound {
		t.Fatalf("unknown connection: %q, %v", path, err)
	}
}

// When the exec-path maps can't be opened along with the socket-owner map,
// they are retried, although the socket-owner map stays the same.
func TestExecMapsRetried(t *testing.T) {
	requireExecMaps(t)
	dir := filepath.Dir(SockOwnerMap())
	pin := fmt.Sprintf("/sys/fs/bpf/mihomo-test-%d", os.Getpid())
	if err := os.Mkdir(pin, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(pin)
	repin := func(name string) {
		fd, err := openPinnedRW(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := pinObject(fd, filepath.Join(pin, name)); err != nil {
			t.Fatal(err)
		}
	}
	repin("conn_owners")
	repin(execRecentMap)
	// A map of the wrong type stands in for exec_tasks.
	attr := struct {
		Type       uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
	}{unix.BPF_MAP_TYPE_ARRAY, 4, 4, 1}
	fd, err := bpfCall(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		t.Fatal(err)
	}
	err = pinObject(int(fd), filepath.Join(pin, execTasksMap))
	unix.Close(int(fd))
	if err != nil {
		t.Fatal(err)
	}

	previous := SockOwnerMap()
	SetSockOwnerMap(filepath.Join(pin, "conn_owners"))
	defer SetSockOwnerMap(previous)
	state := func() (connOpen, execOpen bool) {
		sockOwners.mu.Lock()
		defer sockOwners.mu.Unlock()
		sockOwners.checkedAt = time.Time{} // check the pins on the next lookup
		return sockOwners.fd >= 0, sockOwners.tasksFd >= 0
	}
	state()
	sockOwners.lookup(func(int, uint64) bool { return false })
	if connOpen, execOpen := state(); !connOpen || execOpen {
		t.Fatalf("with a wrong exec_tasks: socket-owner map open %v, exec maps open %v", connOpen, execOpen)
	}
	os.Remove(filepath.Join(pin, execTasksMap))
	repin(execTasksMap)
	sockOwners.lookup(func(int, uint64) bool { return false })
	if connOpen, execOpen := state(); !connOpen || !execOpen {
		t.Fatalf("after fixing exec_tasks: socket-owner map open %v, exec maps open %v", connOpen, execOpen)
	}
}
