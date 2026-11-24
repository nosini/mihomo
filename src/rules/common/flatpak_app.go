package common

import (
	"fmt"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

// FlatpakApp matches connections of a Flatpak app by the systemd scope
// flatpak run starts it in, as named by the cgroup socketowner records for
// the socket's owner. See docs/socketowner.md.
type FlatpakApp struct {
	Base
	appID   string
	adapter string
}

func NewFlatpakApp(appID, adapter string) (*FlatpakApp, error) {
	if !process.ValidFlatpakAppID(appID) {
		return nil, fmt.Errorf("%w: %q is not a Flatpak app ID", errPayload, appID)
	}
	process.WantCgroupLookup()
	return &FlatpakApp{appID: appID, adapter: adapter}, nil
}

func (f *FlatpakApp) RuleType() C.RuleType {
	return C.FlatpakApp
}

// Match compares app IDs exactly, as Flatpak does.
func (f *FlatpakApp) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	return metadata.FlatpakApp != "" && metadata.FlatpakApp == f.appID, f.adapter
}

func (f *FlatpakApp) Adapter() string {
	return f.adapter
}

func (f *FlatpakApp) Payload() string {
	return f.appID
}
