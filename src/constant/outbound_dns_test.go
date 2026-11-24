package constant

import (
	"encoding/json"
	"testing"
)

// The outbound DNS metadata is part of the connection list JSON: present as
// a group when an outbound resolved the destination itself, absent otherwise.
func TestMetadataOutboundDNSJSON(t *testing.T) {
	without := &Metadata{Host: "example.test"}
	blob, err := json.Marshal(without)
	if err != nil {
		t.Fatal(err)
	}
	if jsonHasKey(t, blob, "outboundDns") {
		t.Fatalf("outboundDns present without own nameservers: %s", blob)
	}

	with := &Metadata{Host: "example.test", OutboundDNS: &OutboundDNS{
		Server:    "udp://10.0.0.53:53",
		LocalAddr: "10.0.0.5:53712",
		Interface: "eth0.110",
		Cached:    true,
	}}
	blob, err = json.Marshal(with)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		OutboundDNS *struct {
			Server    string `json:"server"`
			LocalAddr string `json:"localAddr"`
			Interface string `json:"interface"`
			Cached    bool   `json:"cached"`
		} `json:"outboundDns"`
	}
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	dns := decoded.OutboundDNS
	if dns == nil {
		t.Fatalf("outboundDns missing from %s", blob)
	}
	if dns.Server != "udp://10.0.0.53:53" || dns.LocalAddr != "10.0.0.5:53712" ||
		dns.Interface != "eth0.110" || !dns.Cached {
		t.Fatalf("decoded %v from %s", dns, blob)
	}

	// Empty fields are omitted from the group.
	with.OutboundDNS = &OutboundDNS{Server: "tcp://10.0.0.53:53"}
	blob, err = json.Marshal(with.OutboundDNS)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"localAddr", "interface", "cached"} {
		if jsonHasKey(t, blob, key) {
			t.Errorf("%q present in an empty record: %s", key, blob)
		}
	}
}

func jsonHasKey(t *testing.T, blob []byte, key string) bool {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(blob, &object); err != nil {
		t.Fatalf("%s is not an object: %v", blob, err)
	}
	_, ok := object[key]
	return ok
}
