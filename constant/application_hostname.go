package constant

import (
	"errors"
	"net/netip"
	"strings"
)

// ApplicationHostnameRole describes what a verified transport adapter observed.
// ECHInner requires proof of the inner-name role from that adapter; a difference
// from sniffed SNI alone never establishes it.
type ApplicationHostnameRole uint8

const (
	ApplicationHostnameTLS ApplicationHostnameRole = iota + 1
	ApplicationHostnameECHInner
)

// applicationHostname is immutable and scoped to one accepted connection. It is
// deliberately absent from JSON and outbound address encodings.
type applicationHostname struct {
	name         string
	role         ApplicationHostnameRole
	source, dest netip.AddrPort
}

// SetApplicationHostname consumes an already validated, live association before
// route selection. It does not authenticate a publisher or prove correlation;
// the reader must do that before calling it. Only the tested TCP REDIRECT path
// is admitted. There is no production caller until that reader is integrated.
// A second, different observation permanently excludes application evidence on
// this metadata. Callers must never update an established connection's route.
func (m *Metadata) SetApplicationHostname(name string, role ApplicationHostnameRole) error {
	previous := m.applicationHostname
	m.applicationHostname = &applicationHostname{} // failed replacement cannot retain old evidence
	normalized, err := normalizeApplicationHostname(name)
	if err != nil || (role != ApplicationHostnameTLS && role != ApplicationHostnameECHInner) ||
		m.NetWork != TCP || m.Type != REDIR || !m.SourceAddrPort().IsValid() || m.SrcPort == 0 ||
		!m.AddrPort().IsValid() || m.DstPort == 0 || m.DNSMode == DNSFakeIP {
		return errors.New("unusable application hostname association")
	}
	next := applicationHostname{name: normalized, role: role, source: m.SourceAddrPort(), dest: m.AddrPort()}
	if previous != nil && *previous != next {
		return errors.New("conflicting application hostname associations")
	}
	m.applicationHostname = &next
	return nil
}

// ApplicationHostname returns usable rule-only evidence, or an empty string.
// Explicit destinations and Fake-IP keep their existing semantics. A verified
// inner name may differ from outer SNI; an ordinary TLS name may not silently
// override a conflicting sniffed name. DNSMapping is an IP-to-name hint and
// yields to a verified connection association.
func (m *Metadata) ApplicationHostname() string {
	a := m.applicationHostname
	if a == nil || a.name == "" || m.NetWork != TCP || m.Type != REDIR ||
		m.SourceAddrPort() != a.source || m.AddrPort() != a.dest ||
		m.DNSMode == DNSFakeIP || (m.Host != "" && m.DNSMode != DNSMapping) {
		return ""
	}
	if m.SniffHost != "" && a.role != ApplicationHostnameECHInner {
		sniff, err := normalizeApplicationHostname(m.SniffHost)
		if err != nil || sniff != a.name {
			return ""
		}
	}
	return a.name
}

// This deliberately narrow policy accepts ASCII DNS hostnames, including
// already encoded A-labels. It lowercases and removes one terminal root dot;
// it never truncates, trims whitespace or guesses an IDNA conversion.
func normalizeApplicationHostname(name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("invalid application hostname length")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("application hostname is an IP literal")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid application hostname label")
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid application hostname character")
			}
		}
	}
	return strings.ToLower(name), nil
}
