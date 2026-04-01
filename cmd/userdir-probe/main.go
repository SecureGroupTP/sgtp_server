package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:250", "TCP address of SGTP server")
	timeout := flag.Duration("timeout", 3*time.Second, "dial/read/write timeout")
	readDiscovery := flag.Bool("read-discovery", true, "read 25-byte discovery header before probe")
	flag.Parse()

	conn, err := net.DialTimeout("tcp", *addr, *timeout)
	if err != nil {
		fatal("dial %s: %v", *addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	if *readDiscovery {
		d := make([]byte, 25)
		if _, err := io.ReadFull(conn, d); err != nil {
			fatal("failed to read discovery header (25 bytes): %v", err)
		}
	}

	// 1) Route to userdir: 32-byte all-zero prefix.
	if _, err := conn.Write(make([]byte, 32)); err != nil {
		fatal("write userdir routing prefix: %v", err)
	}

	// 2) Send SEARCH request frame (type=0x02) with empty query and limit=1.
	// Payload layout: [ver=1][u16 query_len=0][u16 limit=1]
	payload := []byte{0x01, 0x00, 0x00, 0x00, 0x01}
	frameLen := uint32(1 + len(payload))
	frame := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], frameLen)
	frame[4] = 0x02
	copy(frame[5:], payload)

	if _, err := conn.Write(frame); err != nil {
		fatal("write SEARCH frame: %v", err)
	}

	// 3) Read one response frame.
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		fatal("read response length: %v", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 1 {
		fatal("invalid response frame length: %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		fatal("read response payload: %v", err)
	}

	typ := resp[0]
	body := resp[1:]

	switch typ {
	case 0x83:
		// SEARCH_RESULTS payload starts with [ver][u16 count]
		if len(body) < 3 {
			fatal("SEARCH_RESULTS too short: %d", len(body))
		}
		ver := body[0]
		count := binary.BigEndian.Uint16(body[1:3])
		fmt.Printf("OK: userdir is reachable on %s (response=SEARCH_RESULTS, ver=%d, count=%d)\n", *addr, ver, count)
	case 0x82:
		if len(body) < 4 {
			fatal("ERROR frame too short: %d", len(body))
		}
		code := binary.BigEndian.Uint16(body[0:2])
		msgLen := binary.BigEndian.Uint16(body[2:4])
		if len(body) < int(4+msgLen) {
			fatal("ERROR frame truncated: msg_len=%d body=%d", msgLen, len(body))
		}
		msg := string(body[4 : 4+msgLen])
		fmt.Printf("ERROR: userdir responded with protocol error on %s (code=0x%04x, msg=%q)\n", *addr, code, msg)
		os.Exit(2)
	default:
		fmt.Printf("UNEXPECTED: got response type=0x%02x payload_len=%d (server answered, but not as expected)\n", typ, len(body))
		os.Exit(3)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
