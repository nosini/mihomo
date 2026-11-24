package rules_test

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
)

func TestSystemdUnitRule(t *testing.T) {
	const user = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
	// A Quadlet container's pasta, and its payload.
	pasta := &C.Metadata{
		Process:     "pasta.avx2",
		CgroupPath:  user + "jdownloader.service/runtime",
		SystemdUnit: "jdownloader.service",
	}
	payload := &C.Metadata{
		Process:     "java",
		CgroupPath:  user + "jdownloader.service/libpod-payload-8f7d2ed094aa",
		SystemdUnit: "jdownloader.service",
	}
	other := &C.Metadata{Process: "pasta.avx2", SystemdUnit: "pyload.service"}
	unknown := &C.Metadata{Process: "pasta.avx2"}

	rule, err := rules.ParseRule("SYSTEMD-UNIT", "jdownloader.service", "proxy", nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, C.SystemdUnit, rule.RuleType())
	assert.Equal(t, "SystemdUnit", rule.RuleType().String())
	assert.Equal(t, "jdownloader.service", rule.Payload())
	for m, want := range map[*C.Metadata]bool{pasta: true, payload: true, other: false, unknown: false} {
		got, adapter := rule.Match(m, C.RuleMatchHelper{})
		assert.Equal(t, want, got, "%+v", m)
		assert.Equal(t, "proxy", adapter)
	}

	// The lookup runs only when a rule needs it.
	called := false
	rule.Match(&C.Metadata{}, C.RuleMatchHelper{FindProcess: func() { called = true }})
	assert.True(t, called)

	scope, err := rules.ParseRule("SYSTEMD-UNIT", "podman-2494.scope", "proxy", nil, nil)
	if assert.NoError(t, err) {
		got, _ := scope.Match(&C.Metadata{SystemdUnit: "podman-2494.scope"}, C.RuleMatchHelper{})
		assert.True(t, got)
	}

	and, err := rules.ParseRule("AND", "((PROCESS-NAME-REGEX,^pasta(\\.avx2)?$),(SYSTEMD-UNIT,jdownloader.service))", "proxy", nil, nil)
	if assert.NoError(t, err) {
		for m, want := range map[*C.Metadata]bool{pasta: true, payload: false, other: false} {
			got, _ := and.Match(m, C.RuleMatchHelper{})
			assert.Equal(t, want, got, "%+v", m)
		}
	}
}

func TestSystemdUnitRuleRejectsInvalidNames(t *testing.T) {
	for _, payload := range []string{"", "jdownloader", "user.slice", "default.target", "getty@.service", "*.service", "/app.slice/x.service"} {
		_, err := rules.ParseRule("SYSTEMD-UNIT", payload, "proxy", nil, nil)
		assert.Error(t, err, payload)
	}
	tp, payload, target, params := RC.ParseRulePayload("SYSTEMD-UNIT,jdownloader.service,proxy", true)
	_, err := rules.ParseRule(tp, payload, target, params, nil)
	assert.NoError(t, err)
}
