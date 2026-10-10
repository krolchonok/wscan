package js

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestMySQLActualEmptyUsernameAndPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	identity := make(chan string, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				send := func(seq byte, data []byte) {
					h := []byte{byte(len(data)), byte(len(data) >> 8), byte(len(data) >> 16), seq}
					c.Write(append(h, data...))
				}
				read := func() ([]byte, error) {
					h := make([]byte, 4)
					if _, err := io.ReadFull(c, h); err != nil {
						return nil, err
					}
					n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
					if n > 65536 {
						return nil, io.ErrUnexpectedEOF
					}
					data := make([]byte, n)
					_, err := io.ReadFull(c, data)
					return data, err
				}
				// Protocol 4.1, secure-connection and native-password capabilities.
				caps := uint32(1 | 4 | 512 | 8192 | 32768 | 524288)
				greeting := []byte("\x0a5.7.0\x00\x01\x00\x00\x00abcdefgh\x00")
				low := make([]byte, 2)
				binary.LittleEndian.PutUint16(low, uint16(caps))
				greeting = append(greeting, low...)
				greeting = append(greeting, 33, 2, 0)
				binary.LittleEndian.PutUint16(low, uint16(caps>>16))
				greeting = append(greeting, low...)
				greeting = append(greeting, 21)
				greeting = append(greeting, make([]byte, 10)...)
				greeting = append(greeting, []byte("ijklmnopqrst\x00mysql_native_password\x00")...)
				send(0, greeting)
				login, err := read()
				if err != nil || len(login) < 34 {
					return
				}
				end := 32
				for end < len(login) && login[end] != 0 {
					end++
				}
				if end+1 >= len(login) {
					return
				}
				user := string(login[32:end])
				if login[end+1] != 0 {
					identity <- "NONEMPTY-PASSWORD"
					return
				}
				identity <- user
				send(2, []byte{0, 0, 0, 2, 0, 0, 0})
				for {
					packet, err := read()
					if err != nil || len(packet) == 0 {
						return
					}
					if packet[0] == 1 {
						return
					}
					send(1, []byte{0, 0, 0, 2, 0, 0, 0})
				}
			}(c)
		}
	}()
	client := NewMySQLClient(context.Background(), time.Second)
	for _, user := range []string{"", "root"} {
		ok, err := client.Connect("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, user, "")
		if err != nil || !ok {
			t.Fatalf("user=%q ok=%v err=%v", user, ok, err)
		}
		if got := <-identity; got != user {
			t.Fatalf("wire username=%q want=%q", got, user)
		}
	}
}
