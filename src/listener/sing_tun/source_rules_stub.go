//go:build !linux || android

package sing_tun

import tun "github.com/metacubex/sing-tun"

func fixIPv6SourceRules(tun.Options) error { return nil }
