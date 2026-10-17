//go:build !windows

package sing_tun

import (
	"errors"

	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	device, err := tun.New(options)
	if err != nil {
		return nil, err
	}
	if err := fixIPv6SourceRules(options); err != nil {
		return nil, errors.Join(err, device.Close())
	}
	return device, nil
}
