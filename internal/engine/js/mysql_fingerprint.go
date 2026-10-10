package js

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// FingerprintMySQL reads the server greeting without sending credentials.
func (c *MySQLClient) FingerprintMySQL(host string, port int) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size < 1 || size > 65536 || header[3] != 0 {
		return nil, fmt.Errorf("MySQL: invalid greeting packet")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	if data[0] != 10 {
		return nil, fmt.Errorf("MySQL: unsupported greeting protocol %d", data[0])
	}
	end := strings.IndexByte(string(data[1:]), 0)
	if end < 0 {
		return nil, fmt.Errorf("MySQL: unterminated server version")
	}
	end++
	offset := end + 1
	if len(data) < offset+15 {
		return nil, fmt.Errorf("MySQL: truncated greeting")
	}
	caps := uint32(binary.LittleEndian.Uint16(data[offset+13 : offset+15]))
	if len(data) >= offset+20 {
		caps |= uint32(binary.LittleEndian.Uint16(data[offset+18:offset+20])) << 16
	}
	return map[string]any{"Version": string(data[1:end]), "TLS": caps&0x800 != 0, "Transport": "tcp", "Protocol": int(data[0]), "ConnectionID": binary.LittleEndian.Uint32(data[offset : offset+4])}, nil
}
