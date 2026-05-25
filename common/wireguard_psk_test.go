package common

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestWireguardPreSharedKeyFromUnknownField(t *testing.T) {
	// Wire from Python PasarGuardNodeBridge: public_key, peer_ips, pre_shared_key (field 3)
	raw := []byte{
		0x0a, 0x04, 0x41, 0x41, 0x41, 0x3d,
		0x12, 0x0b, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x2f, 0x33, 0x32,
		0x1a, 0x05, 0x42, 0x42, 0x42, 0x42, 0x3d,
	}
	wg := &Wireguard{}
	if err := proto.Unmarshal(raw, wg); err != nil {
		t.Fatal(err)
	}
	got := WireguardPreSharedKey(wg)
	if got != "BBBB=" {
		t.Fatalf("psk=%q want BBBB=", got)
	}
}
