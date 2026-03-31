package redisresp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Client struct {
	addr string

	dialer net.Dialer
	pool   sync.Pool // *pooledConn

	defaultTimeout time.Duration
}

func New(addr string) *Client {
	c := &Client{
		addr:           addr,
		defaultTimeout: 10 * time.Second,
	}
	c.pool.New = func() any { return (*pooledConn)(nil) }
	return c
}

func (c *Client) SetDefaultTimeout(d time.Duration) {
	if d > 0 {
		c.defaultTimeout = d
	}
}

func (c *Client) Do(ctx context.Context, args ...any) (any, error) {
	pc, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	ok := false
	defer func() {
		if ok {
			c.putConn(pc)
		} else {
			pc.close()
		}
	}()

	if err := pc.applyDeadline(ctx, c.defaultTimeout); err != nil {
		return nil, err
	}
	if err := writeArray(pc.bw, args...); err != nil {
		return nil, err
	}
	if err := pc.bw.Flush(); err != nil {
		return nil, err
	}

	resp, err := readRESP(pc.br)
	if err != nil {
		return nil, err
	}
	ok = true
	return resp, nil
}

func (c *Client) Ping(ctx context.Context) error {
	v, err := c.Do(ctx, "PING")
	if err != nil {
		return err
	}
	if s, ok := v.(string); ok && s == "PONG" {
		return nil
	}
	return fmt.Errorf("redis: unexpected PING response: %T %v", v, v)
}

func (c *Client) SetEX(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	secs := int64(ttl.Seconds())
	if secs <= 0 {
		return fmt.Errorf("redis: ttl must be >0")
	}
	_, err := c.Do(ctx, "SET", key, value, "EX", strconv.FormatInt(secs, 10))
	return err
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := c.Do(ctx, "GET", key)
	if err != nil {
		return nil, false, err
	}
	if v == nil {
		return nil, false, nil
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, false, fmt.Errorf("redis: GET unexpected type %T", v)
	}
	return b, true, nil
}

func (c *Client) SAdd(ctx context.Context, key string, member string) error {
	_, err := c.Do(ctx, "SADD", key, member)
	return err
}

func (c *Client) SRem(ctx context.Context, key string, member string) error {
	_, err := c.Do(ctx, "SREM", key, member)
	return err
}

func (c *Client) SMembers(ctx context.Context, key string) ([]string, error) {
	v, err := c.Do(ctx, "SMEMBERS", key)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("redis: SMEMBERS unexpected type %T", v)
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		b, ok := it.([]byte)
		if !ok {
			return nil, fmt.Errorf("redis: SMEMBERS element unexpected type %T", it)
		}
		out = append(out, string(b))
	}
	return out, nil
}

func (c *Client) MGet(ctx context.Context, keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	args := make([]any, 0, 1+len(keys))
	args = append(args, "MGET")
	for _, k := range keys {
		args = append(args, k)
	}

	v, err := c.Do(ctx, args...)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("redis: MGET unexpected type %T", v)
	}
	if len(arr) != len(keys) {
		return nil, fmt.Errorf("redis: MGET expected %d items, got %d", len(keys), len(arr))
	}
	out := make([][]byte, len(arr))
	for i, it := range arr {
		if it == nil {
			out[i] = nil
			continue
		}
		b, ok := it.([]byte)
		if !ok {
			return nil, fmt.Errorf("redis: MGET element unexpected type %T", it)
		}
		out[i] = b
	}
	return out, nil
}

type pooledConn struct {
	c  net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

func (c *Client) getConn(ctx context.Context) (*pooledConn, error) {
	if v := c.pool.Get(); v != nil {
		if pc, ok := v.(*pooledConn); ok && pc != nil {
			return pc, nil
		}
	}

	nc, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	return &pooledConn{
		c:  nc,
		br: bufio.NewReaderSize(nc, 64*1024),
		bw: bufio.NewWriterSize(nc, 64*1024),
	}, nil
}

func (c *Client) putConn(pc *pooledConn) {
	if pc == nil || pc.c == nil {
		return
	}
	c.pool.Put(pc)
}

func (pc *pooledConn) close() {
	if pc == nil || pc.c == nil {
		return
	}
	_ = pc.c.Close()
}

func (pc *pooledConn) applyDeadline(ctx context.Context, def time.Duration) error {
	if pc == nil || pc.c == nil {
		return errors.New("redis: nil conn")
	}
	if d, ok := ctx.Deadline(); ok {
		return pc.c.SetDeadline(d)
	}
	if def > 0 {
		return pc.c.SetDeadline(time.Now().Add(def))
	}
	return nil
}

func writeArray(w *bufio.Writer, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("redis: empty command")
	}
	if err := writeLine(w, "*"+strconv.Itoa(len(args))); err != nil {
		return err
	}
	for _, a := range args {
		var b []byte
		switch v := a.(type) {
		case string:
			b = []byte(v)
		case []byte:
			b = v
		case int:
			b = []byte(strconv.Itoa(v))
		case int64:
			b = []byte(strconv.FormatInt(v, 10))
		case uint64:
			b = []byte(strconv.FormatUint(v, 10))
		default:
			return fmt.Errorf("redis: unsupported arg type %T", a)
		}
		if err := writeBulk(w, b); err != nil {
			return err
		}
	}
	return nil
}

func writeBulk(w *bufio.Writer, b []byte) error {
	if err := writeLine(w, "$"+strconv.Itoa(len(b))); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err := w.WriteString("\r\n")
	return err
}

func writeLine(w *bufio.Writer, s string) error {
	_, err := w.WriteString(s + "\r\n")
	return err
}

func readRESP(r *bufio.Reader) (any, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch prefix {
	case '+': // simple string
		s, err := readLine(r)
		if err != nil {
			return nil, err
		}
		return s, nil
	case '-': // error
		s, err := readLine(r)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(s)
	case ':': // integer
		s, err := readLine(r)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	case '$': // bulk
		s, err := readLine(r)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		if n < 0 || n > 512*1024*1024 {
			return nil, fmt.Errorf("redis: bulk length %d out of range", n)
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if !bytes.HasSuffix(b, []byte("\r\n")) {
			return nil, fmt.Errorf("redis: invalid bulk terminator")
		}
		return b[:n], nil
	case '*': // array
		s, err := readLine(r)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		if n < 0 || n > 1_000_000 {
			return nil, fmt.Errorf("redis: array length %d out of range", n)
		}
		arr := make([]any, int(n))
		for i := 0; i < int(n); i++ {
			v, err := readRESP(r)
			if err != nil {
				return nil, err
			}
			arr[i] = v
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("redis: unknown prefix %q", prefix)
	}
}

func readLine(r *bufio.Reader) (string, error) {
	b, err := r.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	if len(b) < 2 || b[len(b)-2] != '\r' {
		return "", fmt.Errorf("redis: invalid line terminator")
	}
	return string(b[:len(b)-2]), nil
}
