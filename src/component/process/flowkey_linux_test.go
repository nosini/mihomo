package process

import (
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// The layout of conn_flows in socketowner's docs/map-interface.md.
func TestFlowABILayout(t *testing.T) {
	var k sockFlowKey
	assert.Equal(t, uintptr(48), unsafe.Sizeof(k))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(k.Daddr))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(k.Sport))
	assert.Equal(t, uintptr(42), unsafe.Offsetof(k.Dport))
	assert.Equal(t, uintptr(44), unsafe.Offsetof(k.Proto))
	var v sockFlowValue
	assert.Equal(t, uintptr(24), unsafe.Sizeof(v))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(v.CgroupID))
}

func TestFlowKeys(t *testing.T) {
	key := sockOwnerKey{Netns: 7, Addr: netip.MustParseAddr("198.18.0.1").As16(), Port: 5000, Proto: 6}
	peer := netip.MustParseAddrPort("[::ffff:198.18.0.5]:443")
	keys := flowKeys(key, []netip.AddrPort{
		{}, // no packet destination
		peer,
		netip.MustParseAddrPort("198.18.0.5:443"),               // the same, unmapped
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0), // no inbound port
		netip.MustParseAddrPort("127.0.0.1:7892"),
	})
	if assert.Len(t, keys, 2) {
		assert.Equal(t, sockFlowKey{Netns: 7, Saddr: key.Addr, Daddr: netip.MustParseAddr("198.18.0.5").As16(),
			Sport: 5000, Dport: 443, Proto: 6}, keys[0])
		assert.Equal(t, uint16(7892), keys[1].Dport)
	}
}
