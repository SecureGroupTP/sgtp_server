package userdir

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	msgRegister    byte = 0x01
	msgSearch      byte = 0x02
	msgGetProfile  byte = 0x03
	msgGetMeta     byte = 0x04 // lightweight: no avatar bytes
	msgSubscribe   byte = 0x05 // subscribe to change notifications for a list of pubkeys
	msgUnsubscribe byte = 0x06 // unsubscribe; count=0 means unsubscribe all
	msgFriendReq   byte = 0x07 // signed friend request (requester -> recipient)
	msgFriendResp  byte = 0x08 // signed friend response (recipient -> requester), yes/no
	msgFriendSync  byte = 0x09 // signed snapshot request for current friend states

	msgOK      byte = 0x81
	msgError   byte = 0x82
	msgResults byte = 0x83
	msgProfile byte = 0x84
	msgMeta    byte = 0x85 // response to msgGetMeta
	msgNotify  byte = 0x86 // server-pushed profile-change notification
	msgFState  byte = 0x87 // response to msgFriendSync (friend-state snapshot)
	msgFNotify byte = 0x88 // server-pushed friend notification
)

const (
	errBadRequest uint16 = 0x0001
	errBadSig     uint16 = 0x0002
	errNotFound   uint16 = 0x0003
	errInternal   uint16 = 0x0004
)

// readFrame reads one complete userdir frame from r.
// Returns the message type byte and the payload (type byte excluded).
func readFrame(r io.Reader, maxLen uint32) (byte, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 1 {
		return 0, nil, fmt.Errorf("userdir: invalid frame length %d", n)
	}
	if maxLen > 0 && n > maxLen {
		return 0, nil, fmt.Errorf("userdir: frame length %d exceeds max %d", n, maxLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

// parseGetMeta parses a msgGetMeta request.
// payload: [1B ver][32B pubkey]
func parseGetMeta(payload []byte) (ver byte, pubkey [32]byte, err error) {
	if len(payload) != 1+32 {
		return 0, [32]byte{}, fmt.Errorf("invalid get_meta payload")
	}
	ver = payload[0]
	copy(pubkey[:], payload[1:33])
	return ver, pubkey, nil
}

// parseSubscribe parses msgSubscribe and msgUnsubscribe — they share a wire format.
// payload: [1B ver][2B count][32B pubkey * count]
// For UNSUBSCRIBE, count == 0 means "unsubscribe from all".
func parseSubscribe(payload []byte) (ver byte, pubkeys [][32]byte, err error) {
	if len(payload) < 1+2 {
		return 0, nil, fmt.Errorf("short subscribe payload")
	}
	ver = payload[0]
	count := int(binary.BigEndian.Uint16(payload[1:3]))
	if len(payload) != 1+2+count*32 {
		return 0, nil, fmt.Errorf("subscribe payload length mismatch")
	}
	pubkeys = make([][32]byte, count)
	for i := 0; i < count; i++ {
		copy(pubkeys[i][:], payload[3+i*32:3+(i+1)*32])
	}
	return ver, pubkeys, nil
}

func parseFriendRequest(payload []byte) (ver byte, requester, recipient [32]byte, sigAlg byte, sig []byte, signed []byte, err error) {
	if len(payload) != 1+32+32+1+64 {
		return 0, [32]byte{}, [32]byte{}, 0, nil, nil, fmt.Errorf("invalid friend request payload")
	}
	ver = payload[0]
	copy(requester[:], payload[1:33])
	copy(recipient[:], payload[33:65])
	sigAlg = payload[65]
	sig = append([]byte(nil), payload[66:]...)

	signed = make([]byte, 1+len(payload)-64)
	signed[0] = msgFriendReq
	copy(signed[1:], payload[:len(payload)-64])
	return ver, requester, recipient, sigAlg, sig, signed, nil
}

func parseFriendResponse(payload []byte) (ver byte, responder, requester [32]byte, answer byte, sigAlg byte, sig []byte, signed []byte, err error) {
	if len(payload) != 1+32+32+1+1+64 {
		return 0, [32]byte{}, [32]byte{}, 0, 0, nil, nil, fmt.Errorf("invalid friend response payload")
	}
	ver = payload[0]
	copy(responder[:], payload[1:33])
	copy(requester[:], payload[33:65])
	answer = payload[65]
	sigAlg = payload[66]
	sig = append([]byte(nil), payload[67:]...)

	signed = make([]byte, 1+len(payload)-64)
	signed[0] = msgFriendResp
	copy(signed[1:], payload[:len(payload)-64])
	return ver, responder, requester, answer, sigAlg, sig, signed, nil
}

func parseFriendSync(payload []byte) (ver byte, self [32]byte, sigAlg byte, sig []byte, signed []byte, err error) {
	if len(payload) != 1+32+1+64 {
		return 0, [32]byte{}, 0, nil, nil, fmt.Errorf("invalid friend sync payload")
	}
	ver = payload[0]
	copy(self[:], payload[1:33])
	sigAlg = payload[33]
	sig = append([]byte(nil), payload[34:]...)

	signed = make([]byte, 1+len(payload)-64)
	signed[0] = msgFriendSync
	copy(signed[1:], payload[:len(payload)-64])
	return ver, self, sigAlg, sig, signed, nil
}

func writeFriendSnapshot(states []FriendStateSnapshot) []byte {
	if len(states) > 65535 {
		states = states[:65535]
	}
	payload := make([]byte, 0, 3+len(states)*(32+1+1+16))
	payload = append(payload, 1) // version

	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, uint16(len(states)))
	payload = append(payload, tmp2...)

	for _, st := range states {
		payload = append(payload, st.PeerPubKey[:]...)
		payload = append(payload, st.Status)
		if st.HasRoom {
			payload = append(payload, 1)
			payload = append(payload, st.RoomUUID[:]...)
		} else {
			payload = append(payload, 0)
		}
	}
	return buildFrame(msgFState, payload)
}

func writeFriendNotify(eventType, status byte, actor [32]byte, room *[16]byte) []byte {
	payload := make([]byte, 0, 1+1+32+1+1+16)
	payload = append(payload, 1) // version
	payload = append(payload, eventType)
	payload = append(payload, actor[:]...)
	payload = append(payload, status)
	if room != nil {
		payload = append(payload, 1)
		payload = append(payload, room[:]...)
	} else {
		payload = append(payload, 0)
	}
	return buildFrame(msgFNotify, payload)
}

// writeNotify builds a complete msgNotify frame ready for the send channel.
// Layout (same as msgMeta):
//
//	[1B ver][32B pubkey][2B ulen][username][2B flen][fullname][32B avatar_sha256][8B updated_at_unix_sec]
func writeNotify(p *Profile) ([]byte, error) {
	var payload []byte
	payload = append(payload, 1)
	payload = append(payload, p.PubKey[:]...)

	tmp2 := make([]byte, 2)
	ub := []byte(p.Username)
	fb := []byte(p.FullName)
	binary.BigEndian.PutUint16(tmp2, uint16(len(ub)))
	payload = append(payload, tmp2...)
	payload = append(payload, ub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(fb)))
	payload = append(payload, tmp2...)
	payload = append(payload, fb...)

	payload = append(payload, p.AvatarSHA256[:]...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UpdatedAt.Unix()))
	payload = append(payload, ts[:]...)

	frame := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(1+len(payload)))
	frame[4] = msgNotify
	copy(frame[5:], payload)
	return frame, nil
}
