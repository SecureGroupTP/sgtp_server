package userdir

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	msgRegister   byte = 0x01
	msgSearch     byte = 0x02
	msgGetProfile byte = 0x03
	msgGetMeta    byte = 0x04 // lightweight: returns username/fullname/avatar_sha256/updated_at, no avatar bytes

	msgOK      byte = 0x81
	msgError   byte = 0x82
	msgResults byte = 0x83
	msgProfile byte = 0x84
	msgMeta    byte = 0x85 // response to msgGetMeta
)

const (
	errBadRequest uint16 = 0x0001
	errBadSig     uint16 = 0x0002
	errNotFound   uint16 = 0x0003
	errInternal   uint16 = 0x0004
)

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

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	n := uint32(1 + len(payload))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], n)
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{typ}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeOK(w io.Writer, msg string) error {
	b := []byte(msg)
	if len(b) > 65535 {
		b = b[:65535]
	}
	p := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(p[0:2], uint16(len(b)))
	copy(p[2:], b)
	return writeFrame(w, msgOK, p)
}

func writeError(w io.Writer, code uint16, msg string) error {
	b := []byte(msg)
	if len(b) > 65535 {
		b = b[:65535]
	}
	p := make([]byte, 2+2+len(b))
	binary.BigEndian.PutUint16(p[0:2], code)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(b)))
	copy(p[4:], b)
	return writeFrame(w, msgError, p)
}

// parseGetMeta parses a msgGetMeta request — same wire format as msgGetProfile.
// payload: [1B ver][32B pubkey]
func parseGetMeta(payload []byte) (ver byte, pubkey [32]byte, err error) {
	if len(payload) != 1+32 {
		return 0, [32]byte{}, fmt.Errorf("invalid get_meta payload")
	}
	ver = payload[0]
	copy(pubkey[:], payload[1:33])
	return ver, pubkey, nil
}

// writeMetaResponse sends a msgMeta frame.
// payload: [1B ver][32B pubkey][2B ulen][username][2B flen][fullname][32B avatar_sha256][8B updated_at_unix_sec]
func writeMetaResponse(w io.Writer, p *Profile) error {
	var buf []byte
	buf = append(buf, 1)
	buf = append(buf, p.PubKey[:]...)

	tmp2 := make([]byte, 2)
	ub := []byte(p.Username)
	fb := []byte(p.FullName)

	binary.BigEndian.PutUint16(tmp2, uint16(len(ub)))
	buf = append(buf, tmp2...)
	buf = append(buf, ub...)

	binary.BigEndian.PutUint16(tmp2, uint16(len(fb)))
	buf = append(buf, tmp2...)
	buf = append(buf, fb...)

	buf = append(buf, p.AvatarSHA256[:]...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UpdatedAt.Unix()))
	buf = append(buf, ts[:]...)

	return writeFrame(w, msgMeta, buf)
}
