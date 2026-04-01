package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "69.197.181.219:260", "discovery tcp address")
	timeout := flag.Duration("timeout", 4*time.Second, "dial/read timeout")
	flag.Parse()

	conn, err := net.DialTimeout("tcp", *addr, *timeout)
	if err != nil {
		fatal("dial %s: %v", *addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	buf := make([]byte, 25)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fatal("read 25-byte discovery response: %v", err)
	}

	fmt.Printf("raw_hex=%s\n", hex.EncodeToString(buf))

	flags := buf[0]
	tcp := binary.BigEndian.Uint32(buf[1:5])
	tcptls := binary.BigEndian.Uint32(buf[5:9])
	http := binary.BigEndian.Uint32(buf[9:13])
	httptls := binary.BigEndian.Uint32(buf[13:17])
	ws := binary.BigEndian.Uint32(buf[17:21])
	wstls := binary.BigEndian.Uint32(buf[21:25])

	fmt.Printf("flags=0x%02x\n", flags)
	fmt.Printf("tcp=%d\n", tcp)
	fmt.Printf("tcp_tls=%d\n", tcptls)
	fmt.Printf("http=%d\n", http)
	fmt.Printf("http_tls=%d\n", httptls)
	fmt.Printf("ws=%d\n", ws)
	fmt.Printf("ws_tls=%d\n", wstls)
	fmt.Printf("enabled: tcp=%t tcp_tls=%t http=%t http_tls=%t ws=%t ws_tls=%t\n",
		flags&(1<<0) != 0,
		flags&(1<<1) != 0,
		flags&(1<<2) != 0,
		flags&(1<<3) != 0,
		flags&(1<<4) != 0,
		flags&(1<<5) != 0,
	)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
