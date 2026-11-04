package process

import (
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestWineFlowABILayout(t *testing.T) {
	var v wineFlowValue
	assert.Equal(t, uintptr(1088), unsafe.Sizeof(v))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(v.ServerTgid))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(v.Status))
	assert.Equal(t, uintptr(64), unsafe.Offsetof(v.Image))
}

func wineValue(image string) *wineFlowValue {
	v := &wineFlowValue{}
	encoded := utf16.Encode([]rune(image))
	copy(v.Image[:], encoded)
	v.ImageBytes = uint32(len(encoded) * 2)
	return v
}

func TestWineImage(t *testing.T) {
	for image, want := range map[string][2]string{
		`\??\C:\Program Files\Game\Tbs_Browser.exe`: {"Tbs_Browser.exe", `C:\Program Files\Game\Tbs_Browser.exe`},
		`\\?\d:/games/alpha.exe`:                    {"alpha.exe", `d:\games\alpha.exe`},
		`\??\UNC\srv\share\game.exe`:                {"game.exe", `\\srv\share\game.exe`},
		`\\srv\share\dir\game.exe`:                  {"game.exe", `\\srv\share\dir\game.exe`},
		"C:\\Games\\\U0001F3AE.exe":                 {"\U0001F3AE.exe", "C:\\Games\\\U0001F3AE.exe"},
	} {
		name, path, ok := wineImage(wineValue(image))
		assert.True(t, ok, image)
		assert.Equal(t, want, [2]string{name, path}, image)
	}

	mapped := &wineFlowValue{Encoding: 1, ImageBytes: 9}
	for i, b := range []byte("alpha.exe") {
		mapped.Image[i/2] |= uint16(b) << (8 * (i % 2))
	}
	name, path, ok := wineImage(mapped)
	assert.True(t, ok)
	assert.Equal(t, "alpha.exe", name)
	assert.Equal(t, "alpha.exe", path)

	lowSurrogate := wineValue(`C:\a.exe`)
	lowSurrogate.Image[4] = 0xdc00
	for name, v := range map[string]*wineFlowValue{
		"encoding":       {Encoding: 2, ImageBytes: 2},
		"unnamed":        {Encoding: 1},
		"mapped dot":     {Encoding: 1, ImageBytes: 1, Image: [wineImageBytes / 2]uint16{'.'}},
		"empty":          {},
		"odd":            {ImageBytes: 3},
		"oversized":      {ImageBytes: wineImageBytes + 2},
		"nul":            wineValue("C:\\a\x00b.exe"),
		"surrogate":      {ImageBytes: 2, Image: [wineImageBytes / 2]uint16{0xd800}},
		"low surrogate":  lowSurrogate,
		"relative":       wineValue(`Games\game.exe`),
		"drive relative": wineValue(`C:game.exe`),
		"basename only":  wineValue(`game.exe`),
		"directory":      wineValue(`C:\Games\`),
		"dot dot":        wineValue(`C:\Games\..`),
		"bare UNC":       wineValue(`\??\UNC\srv\share`),
		"empty server":   wineValue(`\\\share\game.exe`),
	} {
		_, _, ok := wineImage(v)
		assert.False(t, ok, name)
	}
}
