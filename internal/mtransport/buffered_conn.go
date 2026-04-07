package mtransport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errBufferFull = errors.New("buffer full")

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type pipeDir struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	closed  bool
	maxSize int

	notify  chan struct{}
	closeCh chan struct{}
}

func newPipeDir(maxSize int) *pipeDir {
	return &pipeDir{
		maxSize: maxSize,
		notify:  make(chan struct{}, 1),
		closeCh: make(chan struct{}),
	}
}

func (d *pipeDir) close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.closeCh)
	}
	d.mu.Unlock()
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

func (d *pipeDir) write(p []byte) (int, error) {
	if d.maxSize > 0 && len(p) > d.maxSize {
		return 0, errBufferFull
	}

	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return 0, io.ErrClosedPipe
		}
		if d.maxSize <= 0 || d.buf.Len()+len(p) <= d.maxSize {
			_, _ = d.buf.Write(p)
			d.mu.Unlock()
			select {
			case d.notify <- struct{}{}:
			default:
			}
			return len(p), nil
		}
		closeCh := d.closeCh
		notify := d.notify
		d.mu.Unlock()

		select {
		case <-notify:
		case <-closeCh:
			return 0, io.ErrClosedPipe
		}
	}
}

func (d *pipeDir) read(p []byte, deadline time.Time) (int, error) {
	for {
		d.mu.Lock()
		if d.buf.Len() > 0 {
			n, _ := d.buf.Read(p)
			d.mu.Unlock()
			// Wake blocked writers that are waiting for free space.
			select {
			case d.notify <- struct{}{}:
			default:
			}
			return n, nil
		}
		closed := d.closed
		d.mu.Unlock()

		if closed {
			return 0, io.EOF
		}

		if deadline.IsZero() {
			select {
			case <-d.notify:
				continue
			case <-d.closeCh:
				continue
			}
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, timeoutErr{}
		}
		t := time.NewTimer(wait)
		select {
		case <-d.notify:
			t.Stop()
			continue
		case <-d.closeCh:
			t.Stop()
			continue
		case <-t.C:
			return 0, timeoutErr{}
		}
	}
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

type bufferedConn struct {
	rd *pipeDir
	wr *pipeDir

	local  net.Addr
	remote net.Addr

	closeOnce *sync.Once
	closeFn   func()

	mu           sync.Mutex
	readDeadline time.Time
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	dl := c.readDeadline
	c.mu.Unlock()
	return c.rd.read(p, dl)
}

func (c *bufferedConn) Write(p []byte) (int, error) { return c.wr.write(p) }

func (c *bufferedConn) Close() error {
	c.closeOnce.Do(c.closeFn)
	return nil
}

func (c *bufferedConn) LocalAddr() net.Addr  { return c.local }
func (c *bufferedConn) RemoteAddr() net.Addr { return c.remote }

func (c *bufferedConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return nil
}

func (c *bufferedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *bufferedConn) SetWriteDeadline(time.Time) error { return nil }

// newBufferedConnPair returns two net.Conn ends connected to each other in
// memory. Each direction has a bounded buffer; when full, writes fail.
// peerIP is used as RemoteAddr() on serverSide for accounting/limits.
func newBufferedConnPair(maxBufferedBytesPerDir int, peerIP string) (serverSide net.Conn, clientSide net.Conn) {
	a2b := newPipeDir(maxBufferedBytesPerDir)
	b2a := newPipeDir(maxBufferedBytesPerDir)
	if peerIP == "" {
		peerIP = "client"
	}

	var once sync.Once
	closeBoth := func() {
		a2b.close()
		b2a.close()
	}

	serverSide = &bufferedConn{
		rd:        b2a,
		wr:        a2b,
		local:     dummyAddr("server"),
		remote:    dummyAddr(peerIP),
		closeOnce: &once,
		closeFn:   closeBoth,
	}
	clientSide = &bufferedConn{
		rd:        a2b,
		wr:        b2a,
		local:     dummyAddr("client"),
		remote:    dummyAddr("server"),
		closeOnce: &once,
		closeFn:   closeBoth,
	}
	return serverSide, clientSide
}
