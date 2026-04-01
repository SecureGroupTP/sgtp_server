package mtransport

import "encoding/binary"

// Ports describes which transports are enabled and which port each transport
// is bound to.
//
// A value of 0 means "disabled / unused".
type Ports struct {
	TCP     uint16
	TCPTLS  uint16
	HTTP    uint16
	HTTPTLS uint16
	WS      uint16
	WSTLS   uint16
}

func (p Ports) AnyEnabled() bool {
	return p.TCP != 0 || p.TCPTLS != 0 || p.HTTP != 0 || p.HTTPTLS != 0 || p.WS != 0 || p.WSTLS != 0
}

func (p Ports) flagsByte() byte {
	var f byte
	if p.TCP != 0 {
		f |= 1 << 0
	}
	if p.TCPTLS != 0 {
		f |= 1 << 1
	}
	if p.HTTP != 0 {
		f |= 1 << 2
	}
	if p.HTTPTLS != 0 {
		f |= 1 << 3
	}
	if p.WS != 0 {
		f |= 1 << 4
	}
	if p.WSTLS != 0 {
		f |= 1 << 5
	}
	return f
}

// DiscoveryResponse returns the fixed 25-byte capabilities response payload.
// Layout:
//   - Byte 0: flags bitfield
//   - Bytes 1..24: 6 uint32 BE ports in fixed order
func (p Ports) DiscoveryResponse() [25]byte {
	var out [25]byte
	out[0] = p.flagsByte()
	binary.BigEndian.PutUint32(out[1:5], uint32(p.TCP))
	binary.BigEndian.PutUint32(out[5:9], uint32(p.TCPTLS))
	binary.BigEndian.PutUint32(out[9:13], uint32(p.HTTP))
	binary.BigEndian.PutUint32(out[13:17], uint32(p.HTTPTLS))
	binary.BigEndian.PutUint32(out[17:21], uint32(p.WS))
	binary.BigEndian.PutUint32(out[21:25], uint32(p.WSTLS))
	return out
}
