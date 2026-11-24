//go:build !linux

package process

// lookupHealth reports the BPF reader as unsupported: the pinned maps are
// only read on Linux, as the other-platform stubs in sockowner_other.go are.
func lookupHealth() *Health {
	return &Health{
		Supported: false,
		Message:   "process lookup through pinned BPF maps is only available on Linux",
	}
}
