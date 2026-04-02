package mtransport

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp_server/server"
)

// WSHandler implements a minimal WebSocket endpoint (binary only) without
// external dependencies.
//
// Each Write(p) becomes one binary WebSocket message; reads concatenate
// received binary messages into a byte stream.
type WSHandler struct {
	Logger *log.Logger
	Relay  *server.Server
	Ctx    context.Context
}

func (h WSHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handle)
	mux.HandleFunc("/sgtp/ws", h.handle)
	mux.HandleFunc("/sgtp", h.handle)
}

func (h WSHandler) handle(w http.ResponseWriter, r *http.Request) {
	if h.Logger == nil {
		h.Logger = log.Default()
	}
	h.Logger.Printf("[ws] request method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		h.Logger.Printf("[ws] reject remote=%s reason=method_not_allowed", r.RemoteAddr)
		return
	}
	if !headerHasToken(r.Header, "Connection", "Upgrade") || !headerHasToken(r.Header, "Upgrade", "websocket") {
		http.Error(w, "upgrade required", http.StatusBadRequest)
		h.Logger.Printf("[ws] reject remote=%s reason=upgrade_required", r.RemoteAddr)
		return
	}
	if strings.ToLower(r.Header.Get("Sec-WebSocket-Version")) != "13" {
		http.Error(w, "unsupported websocket version", http.StatusBadRequest)
		h.Logger.Printf("[ws] reject remote=%s reason=unsupported_version version=%q", r.RemoteAddr, r.Header.Get("Sec-WebSocket-Version"))
		return
	}

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		h.Logger.Printf("[ws] reject remote=%s reason=missing_key", r.RemoteAddr)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		h.Logger.Printf("[ws] reject remote=%s reason=no_hijacker", r.RemoteAddr)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		h.Logger.Printf("[ws] hijack failed remote=%s err=%v", r.RemoteAddr, err)
		return
	}
	remote := conn.RemoteAddr().String()
	h.Logger.Printf("[ws] hijacked remote=%s", remote)

	br := rw.Reader
	bw := rw.Writer

	accept := computeAccept(key)
	_, _ = bw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = bw.WriteString("Upgrade: websocket\r\n")
	_, _ = bw.WriteString("Connection: Upgrade\r\n")
	_, _ = bw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n")
	// Explicitly deny extension negotiation for deterministic frame parsing.
	_, _ = bw.WriteString("Sec-WebSocket-Extensions:\r\n")
	_, _ = bw.WriteString("\r\n")
	if err := bw.Flush(); err != nil {
		h.Logger.Printf("[ws] handshake flush failed remote=%s err=%v", remote, err)
		_ = conn.Close()
		return
	}
	h.Logger.Printf("[ws] handshake complete remote=%s", remote)

	ws := newWSStreamConn(conn, br, bw, 32<<20, h.Logger)
	h.Relay.ServeConn(h.Ctx, ws)
	h.Logger.Printf("[ws] relay ServeConn finished remote=%s", remote)
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func computeAccept(key string) string {
	// RFC 6455: Sec-WebSocket-Accept = base64( SHA1( key + GUID ) )
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type wsStreamConn struct {
	c  net.Conn
	br *bufio.Reader
	bw *bufio.Writer

	logger *log.Logger

	writeMu sync.Mutex

	maxMsgBytes int

	readBuf []byte
	readPos int

	closeOnce sync.Once
}

func newWSStreamConn(c net.Conn, br *bufio.Reader, bw *bufio.Writer, maxMsgBytes int, logger *log.Logger) *wsStreamConn {
	if maxMsgBytes <= 0 {
		maxMsgBytes = 32 << 20
	}
	return &wsStreamConn{
		c:           c,
		br:          br,
		bw:          bw,
		logger:      logger,
		maxMsgBytes: maxMsgBytes,
	}
}

func (w *wsStreamConn) Read(p []byte) (int, error) {
	for {
		if w.readPos < len(w.readBuf) {
			n := copy(p, w.readBuf[w.readPos:])
			w.readPos += n
			if w.readPos >= len(w.readBuf) {
				w.readBuf = nil
				w.readPos = 0
			}
			return n, nil
		}

		msg, err := w.readMessage()
		if err != nil {
			if w.logger != nil {
				w.logger.Printf("[ws] read message failed remote=%s err=%v", w.c.RemoteAddr().String(), err)
			}
			return 0, err
		}
		if w.logger != nil {
			w.logger.Printf("[ws] read message remote=%s bytes=%d", w.c.RemoteAddr().String(), len(msg))
		}
		w.readBuf = msg
		w.readPos = 0
	}
}

func (w *wsStreamConn) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if err := writeWSFrame(w.bw, wsOpBinary, p); err != nil {
		if w.logger != nil {
			w.logger.Printf("[ws] write frame failed remote=%s bytes=%d err=%v", w.c.RemoteAddr().String(), len(p), err)
		}
		return 0, err
	}
	if err := w.bw.Flush(); err != nil {
		if w.logger != nil {
			w.logger.Printf("[ws] flush failed remote=%s bytes=%d err=%v", w.c.RemoteAddr().String(), len(p), err)
		}
		return 0, err
	}
	if w.logger != nil {
		w.logger.Printf("[ws] write binary remote=%s bytes=%d", w.c.RemoteAddr().String(), len(p))
	}
	return len(p), nil
}

func (w *wsStreamConn) Close() error {
	w.closeOnce.Do(func() {
		if w.logger != nil {
			w.logger.Printf("[ws] close begin remote=%s", w.c.RemoteAddr().String())
		}
		w.writeMu.Lock()
		_ = writeWSClose(w.bw, 1000, "")
		_ = w.bw.Flush()
		w.writeMu.Unlock()
		_ = w.c.Close()
		if w.logger != nil {
			w.logger.Printf("[ws] close done remote=%s", w.c.RemoteAddr().String())
		}
	})
	return nil
}

func (w *wsStreamConn) LocalAddr() net.Addr  { return w.c.LocalAddr() }
func (w *wsStreamConn) RemoteAddr() net.Addr { return w.c.RemoteAddr() }
func (w *wsStreamConn) SetDeadline(t time.Time) error {
	return w.c.SetDeadline(t)
}
func (w *wsStreamConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsStreamConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

const (
	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA
)

func (w *wsStreamConn) readMessage() ([]byte, error) {
	var msg []byte
	var started bool

	for {
		fin, op, payload, err := w.readFrame()
		if err != nil {
			return nil, err
		}

		switch op {
		case wsOpPing:
			if w.logger != nil {
				w.logger.Printf("[ws] recv ping remote=%s bytes=%d", w.c.RemoteAddr().String(), len(payload))
			}
			w.writeMu.Lock()
			_ = writeWSFrame(w.bw, wsOpPong, payload)
			_ = w.bw.Flush()
			w.writeMu.Unlock()
			if w.logger != nil {
				w.logger.Printf("[ws] send pong remote=%s bytes=%d", w.c.RemoteAddr().String(), len(payload))
			}
			continue
		case wsOpPong:
			if w.logger != nil {
				w.logger.Printf("[ws] recv pong remote=%s bytes=%d", w.c.RemoteAddr().String(), len(payload))
			}
			continue
		case wsOpClose:
			if w.logger != nil {
				w.logger.Printf("[ws] recv close remote=%s bytes=%d", w.c.RemoteAddr().String(), len(payload))
			}
			w.writeMu.Lock()
			_ = writeWSFrame(w.bw, wsOpClose, payload)
			_ = w.bw.Flush()
			w.writeMu.Unlock()
			return nil, io.EOF
		case wsOpText:
			if started {
				_ = w.Close()
				return nil, errors.New("websocket: unexpected text frame while fragmented message in progress")
			}
			started = true
			msg = append(msg, payload...)
		case wsOpBinary:
			if started {
				_ = w.Close()
				return nil, errors.New("websocket: unexpected binary frame while fragmented message in progress")
			}
			started = true
			msg = append(msg, payload...)
		case wsOpCont:
			if !started {
				_ = w.Close()
				return nil, errors.New("websocket: unexpected continuation frame")
			}
			msg = append(msg, payload...)
		default:
			_ = w.Close()
			return nil, errors.New("websocket: unsupported opcode")
		}

		if len(msg) > w.maxMsgBytes {
			_ = w.Close()
			return nil, errors.New("websocket: message too large")
		}

		if fin && started {
			return msg, nil
		}
	}
}

func (w *wsStreamConn) readFrame() (fin bool, op byte, payload []byte, err error) {
	b0, err := w.br.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}
	b1, err := w.br.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}

	fin = (b0 & 0x80) != 0
	rsv := b0 & 0x70
	op = b0 & 0x0F
	if rsv != 0 {
		return false, 0, nil, errors.New("websocket: RSV bits not supported")
	}

	masked := (b1 & 0x80) != 0
	if !masked {
		return false, 0, nil, errors.New("websocket: client frames must be masked")
	}

	plen7 := int(b1 & 0x7F)
	var plen uint64
	switch plen7 {
	case 126:
		var tmp [2]byte
		if _, err := io.ReadFull(w.br, tmp[:]); err != nil {
			return false, 0, nil, err
		}
		plen = uint64(binary.BigEndian.Uint16(tmp[:]))
	case 127:
		var tmp [8]byte
		if _, err := io.ReadFull(w.br, tmp[:]); err != nil {
			return false, 0, nil, err
		}
		plen = binary.BigEndian.Uint64(tmp[:])
	default:
		plen = uint64(plen7)
	}

	if plen > uint64(w.maxMsgBytes) {
		return false, 0, nil, errors.New("websocket: frame too large")
	}

	var maskKey [4]byte
	if _, err := io.ReadFull(w.br, maskKey[:]); err != nil {
		return false, 0, nil, err
	}

	payload = make([]byte, int(plen))
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= maskKey[i&3]
	}
	return fin, op, payload, nil
}

func writeWSFrame(w *bufio.Writer, opcode byte, payload []byte) error {
	const fin = 0x80
	b0 := fin | (opcode & 0x0F)
	if err := w.WriteByte(b0); err != nil {
		return err
	}

	n := len(payload)
	switch {
	case n < 126:
		if err := w.WriteByte(byte(n)); err != nil {
			return err
		}
	case n <= 0xFFFF:
		if err := w.WriteByte(126); err != nil {
			return err
		}
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(n))
		if _, err := w.Write(tmp[:]); err != nil {
			return err
		}
	default:
		if err := w.WriteByte(127); err != nil {
			return err
		}
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], uint64(n))
		if _, err := w.Write(tmp[:]); err != nil {
			return err
		}
	}

	_, err := w.Write(payload)
	return err
}

func writeWSClose(w *bufio.Writer, code uint16, reason string) error {
	var payload []byte
	if code != 0 || reason != "" {
		tmp := make([]byte, 2+len(reason))
		binary.BigEndian.PutUint16(tmp[:2], code)
		copy(tmp[2:], reason)
		payload = tmp
	}
	return writeWSFrame(w, wsOpClose, payload)
}
