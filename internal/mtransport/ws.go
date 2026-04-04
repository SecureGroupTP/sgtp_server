package mtransport

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp_server/server"
	"github.com/gorilla/websocket"
)

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
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.Logger.Printf("[ws] upgrade failed remote=%s err=%v", r.RemoteAddr, err)
		return
	}
	remote := conn.RemoteAddr().String()
	h.Logger.Printf("[ws] upgrade complete remote=%s", remote)

	ws := newWSStreamConn(conn, 32<<20, h.Logger)
	h.Relay.ServeConn(h.Ctx, ws)
	h.Logger.Printf("[ws] relay ServeConn finished remote=%s", remote)
}

type wsStreamConn struct {
	c *websocket.Conn

	logger *log.Logger

	readMu  sync.Mutex
	writeMu sync.Mutex

	maxMsgBytes int

	readBuf []byte
	readPos int

	closeOnce sync.Once
}

func newWSStreamConn(c *websocket.Conn, maxMsgBytes int, logger *log.Logger) *wsStreamConn {
	if maxMsgBytes <= 0 {
		maxMsgBytes = 32 << 20
	}
	c.SetReadLimit(int64(maxMsgBytes))
	return &wsStreamConn{
		c:           c,
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

	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		if w.logger != nil {
			w.logger.Printf("[ws] write frame failed remote=%s bytes=%d err=%v", w.c.RemoteAddr().String(), len(p), err)
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
		_ = w.c.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(2*time.Second),
		)
		w.writeMu.Unlock()
		_ = w.c.Close()
		if w.logger != nil {
			w.logger.Printf("[ws] close done remote=%s", w.c.RemoteAddr().String())
		}
	})
	return nil
}

func (w *wsStreamConn) LocalAddr() net.Addr  { return w.c.UnderlyingConn().LocalAddr() }
func (w *wsStreamConn) RemoteAddr() net.Addr { return w.c.UnderlyingConn().RemoteAddr() }
func (w *wsStreamConn) SetDeadline(t time.Time) error {
	if err := w.c.SetReadDeadline(t); err != nil {
		return err
	}
	return w.c.SetWriteDeadline(t)
}
func (w *wsStreamConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsStreamConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

func (w *wsStreamConn) readMessage() ([]byte, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	for {
		msgType, msg, err := w.c.ReadMessage()
		if err != nil {
			return nil, err
		}
		if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
			continue
		}
		if len(msg) > w.maxMsgBytes {
			return nil, websocket.ErrReadLimit
		}
		if w.logger != nil {
			w.logger.Printf("[ws] read message remote=%s bytes=%d type=%d", w.c.RemoteAddr().String(), len(msg), msgType)
		}
		return msg, nil
	}
}
