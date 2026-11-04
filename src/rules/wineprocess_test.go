package rules_test

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
)

// A relayed Wine connection carries the sandbox's relay as its process and the
// Windows program separately; each rule family sees only its own field.
func TestWineProcessRules(t *testing.T) {
	relayed := &C.Metadata{
		Process:         "game-pasta.avx2",
		ProcessPath:     "/usr/bin/game-pasta.avx2",
		WineProcess:     "Game.exe",
		WineProcessPath: `C:\Games\Game\Game.exe`,
	}
	unknown := &C.Metadata{Process: "game-pasta.avx2", WineProcess: "wine-unknown", WineProcessPath: "wine-unknown"}
	native := &C.Metadata{Process: "game.exe", ProcessPath: "/opt/game.exe"}

	for _, tt := range []struct {
		tp, payload string
		want        []bool // relayed, unknown, native
	}{
		{"WINE-PROCESS-NAME", "game.exe", []bool{true, false, false}},
		{"WINE-PROCESS-NAME", "wine-unknown", []bool{false, true, false}},
		{"WINE-PROCESS-NAME-REGEX", `^game\.exe$`, []bool{true, false, false}},
		{"WINE-PROCESS-NAME-WILDCARD", "*.exe", []bool{true, false, false}},
		{"WINE-PROCESS-PATH", `c:\games\game\game.exe`, []bool{true, false, false}},
		{"WINE-PROCESS-PATH-REGEX", `^C:\\Games\\`, []bool{true, false, false}},
		{"WINE-PROCESS-PATH-WILDCARD", `C:\Games\*`, []bool{true, false, false}},
		{"PROCESS-NAME", "game.exe", []bool{false, false, true}},
		{"PROCESS-NAME-REGEX", `^game-pasta(\.avx2)?$`, []bool{true, true, false}},
	} {
		rule, err := rules.ParseRule(tt.tp, tt.payload, "DIRECT", nil, nil)
		if !assert.NoError(t, err, tt.tp) {
			continue
		}
		for i, m := range []*C.Metadata{relayed, unknown, native} {
			got, adapter := rule.Match(m, C.RuleMatchHelper{})
			assert.Equal(t, tt.want[i], got, "%s,%s on %+v", tt.tp, tt.payload, m)
			assert.Equal(t, "DIRECT", adapter)
		}
	}

	and, err := rules.ParseRule("AND", `((PROCESS-NAME-REGEX,^game-pasta(\.avx2)?$),(WINE-PROCESS-NAME,game.exe))`, "DIRECT", nil, nil)
	if assert.NoError(t, err) {
		for m, want := range map[*C.Metadata]bool{relayed: true, unknown: false, native: false} {
			got, _ := and.Match(m, C.RuleMatchHelper{})
			assert.Equal(t, want, got, "%+v", m)
		}
	}
}

// Regexes may contain commas, which the rule line's own commas must not split.
func TestWineProcessRegexWithComma(t *testing.T) {
	m := &C.Metadata{WineProcess: "alphabeta.exe", WineProcessPath: `C:\Games\alphabeta.exe`}
	for _, line := range []string{
		`WINE-PROCESS-NAME-REGEX,^(alpha|beta){1,2}\.exe$,REJECT`,
		`WINE-PROCESS-PATH-REGEX,^C:\\Games\\(alpha|beta){1,2}\.exe$,REJECT`,
		`AND,((WINE-PROCESS-NAME-REGEX,^(alpha|beta){1,2}\.exe$),(WINE-PROCESS-PATH-REGEX,^C:\\(Games|Apps){1,1}\\)),REJECT`,
	} {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := rules.ParseRule(tp, payload, target, params, nil)
		if !assert.NoError(t, err, line) {
			continue
		}
		matched, adapter := rule.Match(m, C.RuleMatchHelper{})
		assert.True(t, matched, line)
		assert.Equal(t, "REJECT", adapter, line)
	}
}

func TestWineProcessSourceDetail(t *testing.T) {
	m := &C.Metadata{Process: "game-pasta", WineProcess: "game.exe", Uid: 1000}
	assert.Contains(t, m.SourceDetail(), "(game-pasta, wine=game.exe, uid=1000)")
	// The Wine record can be found when the socket's owner isn't.
	m = &C.Metadata{WineProcess: "game.exe"}
	assert.True(t, strings.HasSuffix(m.SourceDetail(), "(wine=game.exe)"), m.SourceDetail())
}
