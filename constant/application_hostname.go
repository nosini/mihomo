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
	validate     func() bool
}

// SetApplicationHostname consumes an already validated, live association before
// route selection. It does not authenticate a publisher or prove correlation;
// the reader must do that before calling it. Only the tested TCP REDIRECT path
// is admitted. The native tunnel supplies evidence only through its configured
// reader on that admitted path.
// validate must perform a bounded fresh check of the same reader/flow/record;
// the tunnel calls it after rule matching and before committing the route.
// A second, different observation permanently excludes application evidence on
// this metadata. Callers must never update an established connection's route.
func (m *Metadata) SetApplicationHostname(name string, role ApplicationHostnameRole, validate func() bool) error {
	previous := m.applicationHostname
	m.applicationHostname = &applicationHostname{} // failed replacement cannot retain old evidence
	normalized, err := normalizeApplicationHostname(name)
	if err != nil || validate == nil || (role != ApplicationHostnameTLS && role != ApplicationHostnameECHInner) ||
		m.NetWork != TCP || m.Type != REDIR || !m.SourceAddrPort().IsValid() || m.SrcPort == 0 ||
		!m.AddrPort().IsValid() || m.DstPort == 0 || m.DNSMode == DNSFakeIP {
		return errors.New("unusable application hostname association")
	}
	next := applicationHostname{name: normalized, role: role, source: m.SourceAddrPort(), dest: m.AddrPort(), validate: validate}
	if previous != nil {
		if previous.name != next.name || previous.role != next.role || previous.source != next.source || previous.dest != next.dest {
			return errors.New("conflicting application hostname associations")
		}
		m.applicationHostname = previous // identical text cannot replace its original authority
		return nil
	}
	m.applicationHostname = &next
	return nil
}

// ConfirmApplicationHostname is the final consumption check after rule matching.
// A false result requires routing again from metadata without application
// evidence. The callback must perform a bounded fresh authority/record read.
func (m *Metadata) ConfirmApplicationHostname() bool {
	a := m.applicationHostname
	if m.ApplicationHostname() == "" || a.validate == nil || !a.validate() || m.ApplicationHostname() == "" {
		m.applicationHostname = &applicationHostname{}
		return false
	}
	return true
}

// WithoutApplicationHostname captures an independent fallback before any
// application-dependent preprocessing, sniffing or rule effects are applied.
func (m *Metadata) WithoutApplicationHostname() *Metadata {
	copy := m.Clone()
	copy.applicationHostname = nil
	return copy
}

// HasApplicationHostname reports tentative evidence, before source selection.
func (m *Metadata) HasApplicationHostname() bool {
	return m.applicationHostname != nil && m.applicationHostname.name != ""
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
		// Rules call this once each; compare without allocating. A valid name is
		// ASCII, so EqualFold applies only ASCII case folding.
		sniff := strings.TrimSuffix(m.SniffHost, ".")
		if !validApplicationHostname(sniff) || !strings.EqualFold(sniff, a.name) {
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
	if !validApplicationHostname(name) {
		return "", errors.New("invalid application hostname")
	}
	return strings.ToLower(name), nil
}

// validApplicationHostname checks a name without its terminal root dot.
func validApplicationHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	numeric, label := true, 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if label == 0 || label > 63 || name[i-label] == '-' || name[i-1] == '-' {
				return false
			}
			label = 0
			continue
		}
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
		numeric = numeric && c >= '0' && c <= '9'
		label++
	}
	// Other IP literals contain characters rejected above.
	if numeric {
		if _, err := netip.ParseAddr(name); err == nil {
			return false
		}
	}
	return true
}
