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

func TestWineImagePath(t *testing.T) {
	path, ok := wineImagePath(wineValue(`\??\C:\Program Files\Game\Tbs_Browser.exe`))
	assert.True(t, ok)
	assert.Equal(t, `C:\Program Files\Game\Tbs_Browser.exe`, path)
	assert.Equal(t, "Tbs_Browser.exe", ProcessBaseName(path))
	assert.Equal(t, "firefox", ProcessBaseName("/usr/bin/firefox"))
	assert.Equal(t, WineUnknown, ProcessBaseName(WineUnknown))

	for name, v := range map[string]*wineFlowValue{
		"empty":     {},
		"odd":       {ImageBytes: 3},
		"oversized": {ImageBytes: wineImageBytes + 2},
		"nul":       wineValue("C:\\a\x00b.exe"),
		"surrogate": {ImageBytes: 2, Image: [wineImageBytes / 2]uint16{0xd800}},
	} {
		_, ok := wineImagePath(v)
		assert.False(t, ok, name)
	}
}
