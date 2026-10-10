package js

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lib/pq"
)

type PGAuthentication struct {
	Connected      bool   `json:"connected"`
	Authentication string `json:"authentication"`
}

// AuditConnect records authentication messages on the same connection used by
// lib/pq, so a password ignored by a trust rule is never called a weak password.
func (c *PGClient) AuditConnect(host string, port int, user, pass string) (PGAuthentication, error) {
	result := PGAuthentication{Authentication: "unknown"}
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(user, pass), Host: joinAddr(host, port), Path: "/postgres"}
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	connector, err := pq.NewConnector(u.String())
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	connector.Dialer(&pgAuditDialer{ctx: ctx, timeout: c.timeout, result: &result})
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	err = db.PingContext(ctx)
	result.Connected = err == nil
	var rejection *pq.Error
	if err != nil && ((errors.As(err, &rejection) && rejection.Code == "28P01") || strings.Contains(err.Error(), "empty password returned by client")) {
		err = nil
	}
	return result, err
}
func (c *PGClient) ConnectWithPassword(host string, port int, user, pass string) (bool, error) {
	r, err := c.AuditConnect(host, port, user, pass)
	return r.Connected && (r.Authentication == "cleartext-password" || r.Authentication == "md5-password" || r.Authentication == "sasl"), err
}

type pgAuditDialer struct {
	ctx     context.Context
	timeout time.Duration
	result  *PGAuthentication
}

func (d *pgAuditDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(d.ctx, network, address)
}
func (d *pgAuditDialer) DialTimeout(network, address string, _ time.Duration) (net.Conn, error) {
	return d.Dial(network, address)
}
func (d *pgAuditDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(d.timeout)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return &pgAuditConn{Conn: conn, result: d.result, stop: stop}, nil
}

type pgAuditConn struct {
	net.Conn
	result   *PGAuthentication
	stop     func() bool
	pending  []byte
	observed bool
}

func (c *pgAuditConn) Close() error { c.stop(); return c.Conn.Close() }
func (c *pgAuditConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.observed {
		c.pending = append(c.pending, p[:n]...)
		for len(c.pending) >= 5 {
			length := int(binary.BigEndian.Uint32(c.pending[1:5]))
			if length < 4 || length > 65536 {
				return n, fmt.Errorf("PostgreSQL: malformed authentication frame")
			}
			if len(c.pending) < length+1 {
				break
			}
			if c.pending[0] == 'R' && length >= 8 {
				method := binary.BigEndian.Uint32(c.pending[5:9])
				switch method {
				case 0:
					c.result.Authentication = "none"
				case 3:
					c.result.Authentication = "cleartext-password"
				case 5:
					c.result.Authentication = "md5-password"
				case 10:
					c.result.Authentication = "sasl"
				default:
					c.result.Authentication = fmt.Sprintf("method-%d", method)
				}
				c.observed = true
				c.pending = nil
				break
			}
			c.pending = c.pending[length+1:]
		}
	}
	return n, err
}
