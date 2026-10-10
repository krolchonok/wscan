// Package telnet implements a bounded, command-free Telnet login exchange.
package telnet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var usernamePrompt = regexp.MustCompile(`(?i)(?:login(?: as)?|username|user name)\s*:\s*$`)
var passwordPrompt = regexp.MustCompile(`(?i)(?:password|passcode)\s*:\s*$`)
var shellPrompt = regexp.MustCompile(`(?:^|\n)[^\r\n]*[#$>]\s*$`)
var ansi = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// Login never runs a command. An unrecognized response is an error, not a rejection.
func Login(ctx context.Context, conn net.Conn, timeout time.Duration, user, password string) (bool, error) {
	defer conn.Close()
	if strings.ContainsAny(user+password, "\r\n\xff") {
		return false, fmt.Errorf("Telnet: invalid credential characters")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return false, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	reader := bufio.NewReader(conn)
	stage := 0
	var text strings.Builder
	for count := 0; count < 65536; count++ {
		b, err := reader.ReadByte()
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, fmt.Errorf("Telnet: incomplete login exchange: %w", err)
		}
		if b == 255 {
			cmd, err := reader.ReadByte()
			if err != nil {
				return false, err
			}
			switch cmd {
			case 255:
				b = 255
			case 251, 252, 253, 254:
				option, err := reader.ReadByte()
				if err != nil {
					return false, err
				}
				// Refuse optional features; do not loop replying to WONT/DONT.
				if cmd == 251 || cmd == 253 {
					reply := byte(254)
					if cmd == 253 {
						reply = 252
					}
					if _, err = conn.Write([]byte{255, reply, option}); err != nil {
						return false, err
					}
				}
				continue
			case 250:
				// Subnegotiation may span packets. Consume up to the shared byte bound.
				prev := byte(0)
				for {
					count++
					if count >= 65536 {
						return false, fmt.Errorf("Telnet: negotiation too large")
					}
					v, err := reader.ReadByte()
					if err != nil {
						return false, err
					}
					if prev == 255 && v == 240 {
						break
					}
					if prev == 255 && v == 255 {
						prev = 0
					} else {
						prev = v
					}
				}
				continue
			default:
				continue
			}
		}
		if b == 0 {
			continue
		}
		text.WriteByte(b)
		if text.Len() > 4096 {
			tail := text.String()[text.Len()-2048:]
			text.Reset()
			text.WriteString(tail)
		}
		clean := ansi.ReplaceAllString(text.String(), "")
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "login incorrect") || strings.Contains(lower, "login failed") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "access denied") || strings.Contains(lower, "invalid password") {
			return false, nil
		}
		if stage == 0 && usernamePrompt.MatchString(clean) {
			if _, err = conn.Write([]byte(user + "\r\n")); err != nil {
				return false, err
			}
			stage = 1
			text.Reset()
			continue
		}
		if (stage == 0 || stage == 1) && passwordPrompt.MatchString(clean) {
			if _, err = conn.Write([]byte(password + "\r\n")); err != nil {
				return false, err
			}
			stage = 2
			text.Reset()
			continue
		}
		if stage == 2 {
			if usernamePrompt.MatchString(clean) || passwordPrompt.MatchString(clean) {
				return false, nil
			}
			if shellPrompt.MatchString(clean) && !strings.HasPrefix(password, strings.TrimSpace(clean)) {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("Telnet: response exceeds 64 KiB")
}
