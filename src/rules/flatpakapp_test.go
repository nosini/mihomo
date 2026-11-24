package rules_test

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
)

func TestFlatpakAppRule(t *testing.T) {
	jd := &C.Metadata{
		Process:    "java",
		CgroupPath: `/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.jdownloader.JDownloader-1873420961.scope`,
		FlatpakApp: "org.jdownloader.JDownloader",
	}
	other := &C.Metadata{Process: "java", FlatpakApp: "org.example.Other"}
	native := &C.Metadata{Process: "java", CgroupPath: "/user.slice/user-1000.slice/session-2.scope"}

	rule, err := rules.ParseRule("FLATPAK-APP", "org.jdownloader.JDownloader", "proxy", nil, nil)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, C.FlatpakApp, rule.RuleType())
	assert.Equal(t, "FlatpakApp", rule.RuleType().String())
	assert.Equal(t, "org.jdownloader.JDownloader", rule.Payload())
	for m, want := range map[*C.Metadata]bool{jd: true, other: false, native: false} {
		got, adapter := rule.Match(m, C.RuleMatchHelper{})
		assert.Equal(t, want, got, "%+v", m)
		assert.Equal(t, "proxy", adapter)
	}

	// App IDs are case-sensitive, as in Flatpak.
	upper, err := rules.ParseRule("FLATPAK-APP", "org.jdownloader.jdownloader", "proxy", nil, nil)
	if assert.NoError(t, err) {
		got, _ := upper.Match(jd, C.RuleMatchHelper{})
		assert.False(t, got)
	}

	// The lookup runs only when a rule needs it.
	called := false
	rule.Match(&C.Metadata{}, C.RuleMatchHelper{FindProcess: func() { called = true }})
	assert.True(t, called)

	and, err := rules.ParseRule("AND", "((PROCESS-NAME,java),(FLATPAK-APP,org.jdownloader.JDownloader))", "proxy", nil, nil)
	if assert.NoError(t, err) {
		for m, want := range map[*C.Metadata]bool{jd: true, other: false, native: false} {
			got, _ := and.Match(m, C.RuleMatchHelper{})
			assert.Equal(t, want, got, "%+v", m)
		}
	}
}

func TestFlatpakAppRuleRejectsInvalidIDs(t *testing.T) {
	for _, payload := range []string{"", "java", "org.example", "org.ex-ample.App", "org.example.*", "/app.slice"} {
		_, err := rules.ParseRule("FLATPAK-APP", payload, "proxy", nil, nil)
		assert.Error(t, err, payload)
	}
	tp, payload, target, params := RC.ParseRulePayload("FLATPAK-APP,org.jdownloader.JDownloader,proxy", true)
	_, err := rules.ParseRule(tp, payload, target, params, nil)
	assert.NoError(t, err)
}
