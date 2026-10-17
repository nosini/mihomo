//go:build linux && !android

package sing_tun

import (
	"fmt"
	"net/netip"

	tun "github.com/metacubex/sing-tun"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// sing-tun 0.4.27 bypasses all known IPv6 sources before looking up TUN
// sources. Move only its two blanket bypasses behind its existing source
// lookups. Keep the rules in sing-tun's owned priority range so Close removes
// them normally. Linux doesn't reset these rules on interface updates.
func fixIPv6SourceRules(options tun.Options) error {
	if !options.AutoRoute || options.AutoRedirectMarkMode || options.FileDescriptor != 0 || len(options.Inet6Address) == 0 {
		return nil
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("read IPv6 TUN source rules: %w", err)
	}
	for _, rule := range ipv6SourceBypasses(options, rules) {
		if err := netlink.RuleDel(&rule); err != nil {
			return fmt.Errorf("remove IPv6 TUN source bypass: %w", err)
		}
		// Equal-priority additions follow the existing source lookups.
		rule.Priority = ipv6SourcePriority(options, rules)
		if err := netlink.RuleAdd(&rule); err != nil {
			return fmt.Errorf("reorder IPv6 TUN source bypass: %w", err)
		}
	}
	return nil
}

func ipv6SourcePriority(options tun.Options, rules []netlink.Rule) int {
	priority := -1
	for _, rule := range rules {
		if rule.Priority < options.IPRoute2RuleIndex || rule.Priority > options.IPRoute2RuleIndex+10 || rule.Table != options.IPRoute2TableIndex || rule.IifName != "lo" {
			continue
		}
		for _, prefix := range options.Inet6Address {
			if rule.Src == prefix.Masked() && rule.Priority > priority {
				priority = rule.Priority
			}
		}
	}
	return priority
}

func ipv6SourceBypasses(options tun.Options, rules []netlink.Rule) []netlink.Rule {
	priority := ipv6SourcePriority(options, rules)
	var bypasses []netlink.Rule
	for _, rule := range rules {
		if rule.Priority < options.IPRoute2RuleIndex || rule.Priority >= priority || rule.Goto != options.IPRoute2RuleIndex+10 || rule.IifName != "lo" || rule.Invert || rule.Dst.IsValid() || rule.OifName != "" || rule.UIDRange != nil || rule.Dport != nil || rule.Sport != nil || rule.Mark != 0 || rule.IPProto != 0 {
			continue
		}
		if rule.Src == netip.MustParsePrefix("::/1") || rule.Src == netip.MustParsePrefix("8000::/1") {
			// RuleList does not preserve the action type and reports table
			// zero for GOTO rules. Restore their action before re-encoding.
			rule.Type, rule.Table = unix.FR_ACT_GOTO, -1
			bypasses = append(bypasses, rule)
		}
	}
	return bypasses
}
