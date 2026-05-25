package common

import "google.golang.org/protobuf/encoding/protowire"

// WireguardPreSharedKey reads pre_shared_key (proto field 3) from a Wireguard message.
// Works before service.pb.go is regenerated: field 3 arrives as unknown wire data.
func WireguardPreSharedKey(wg *Wireguard) string {
	if wg == nil {
		return ""
	}
	return stringFromUnknown(wg.ProtoReflect().GetUnknown(), 3)
}

func stringFromUnknown(unknown []byte, fieldNum protowire.Number) string {
	b := unknown
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == fieldNum && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(b)
			return string(v)
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			break
		}
		b = b[n:]
	}
	return ""
}
