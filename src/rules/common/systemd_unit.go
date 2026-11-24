package common

import (
	"fmt"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

// SystemdUnit matches connections whose owner runs in a systemd service or
// scope, by the cgroup socketowner records for the socket's owner. A Quadlet
// container's pasta runs in its service, so this routes rootless Podman
// containers too. See docs/socketowner.md.
type SystemdUnit struct {
	Base
	unit    string
	adapter string
}

func NewSystemdUnit(unit, adapter string) (*SystemdUnit, error) {
	if !process.ValidSystemdUnitName(unit) {
		return nil, fmt.Errorf("%w: %q is not a systemd service or scope name", errPayload, unit)
	}
	process.WantCgroupLookup()
	return &SystemdUnit{unit: unit, adapter: adapter}, nil
}

func (s *SystemdUnit) RuleType() C.RuleType {
	return C.SystemdUnit
}

// Match compares unit names exactly, as systemd does.
func (s *SystemdUnit) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	return metadata.SystemdUnit != "" && metadata.SystemdUnit == s.unit, s.adapter
}

func (s *SystemdUnit) Adapter() string {
	return s.adapter
}

func (s *SystemdUnit) Payload() string {
	return s.unit
}
