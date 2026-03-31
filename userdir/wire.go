package userdir

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	msgRegister   byte = 0x01
	msgSearch     byte = 0x02
	msgGetProfile byte = 0x03

	msgOK      byte = 0x81
	msgError   byte = 0x82
	msgResults byte = 0x83
	msgProfile byte = 0x84
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
