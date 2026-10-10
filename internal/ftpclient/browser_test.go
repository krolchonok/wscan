package ftpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testFTP struct {
	options  Options
	mu       sync.Mutex
	commands []string
	body     string
}

func fakeFTP(t *testing.T, mode string, mlsd bool) *testFTP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	server := &testFTP{options: Options{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Mode: mode, Insecure: mode != "ftp", Username: "root", Password: "root", Timeout: 3 * time.Second}, body: strings.Repeat("hello FTP\n", 10000)}
	go func() {
		for {
			control, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if mode == "implicit" {
					c = tls.Server(c, tlsConfig)
					defer c.Close()
				}
				reply := func(code int, text string) { fmt.Fprintf(c, "%d %s\r\n", code, text) }
				reader := bufio.NewReader(c)
				reply(220, "local FTP fixture")
				pwd := "/"
				user := ""
				protected := false
				var data net.Listener
				defer func() {
					if data != nil {
						data.Close()
					}
				}()
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					command, arg, _ := strings.Cut(line, " ")
					// Retain command verbs only so the test never records passwords.
					server.mu.Lock()
					server.commands = append(server.commands, command)
					server.mu.Unlock()
					switch command {
					case "AUTH":
						reply(234, "TLS ready")
						secure := tls.Server(c, tlsConfig)
						if secure.Handshake() != nil {
							return
						}
						c = secure
						reader = bufio.NewReader(c)
					case "USER":
						user = arg
						reply(331, "Password required")
					case "PASS":
						if (user == "root" && arg == "root") || (user == "anonymous" && arg == "anonymous@") {
							reply(230, "Logged in")
						} else {
							reply(530, "Login incorrect")
						}
					case "FEAT":
						if mlsd {
							io.WriteString(c, "211-Features\r\n MLST type*;size*;modify*;\r\n UTF8\r\n211 End\r\n")
						} else {
							reply(211, "No features")
						}
					case "TYPE", "OPTS", "PBSZ":
						reply(200, "OK")
					case "PROT":
						protected = arg == "P"
						reply(200, "OK")
					case "PWD":
						reply(257, fmt.Sprintf("%q is current directory", pwd))
					case "CWD":
						if arg == "/denied" {
							reply(550, "Access denied")
						} else {
							pwd = arg
							reply(250, "Directory changed")
						}
					case "EPSV", "PASV":
						if command == "EPSV" && !mlsd {
							reply(502, "EPSV unsupported")
							continue
						}
						if data != nil {
							data.Close()
						}
						data, err = net.Listen("tcp", "127.0.0.1:0")
						if err != nil {
							return
						}
						port := data.Addr().(*net.TCPAddr).Port
						if command == "EPSV" {
							reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
						} else {
							reply(227, fmt.Sprintf("Entering Passive Mode (192,0,2,50,%d,%d)", port/256, port%256))
						}
					case "MLSD", "LIST", "RETR":
						if data == nil {
							reply(425, "No data socket")
							continue
						}
						reply(150, "Opening data")
						transfer, err := data.Accept()
						data.Close()
						data = nil
						if err != nil {
							return
						}
						transfer.SetDeadline(time.Now().Add(3 * time.Second))
						if protected {
							transfer = tls.Server(transfer, tlsConfig)
						}
						switch command {
						case "MLSD":
							fmt.Fprintf(transfer, "type=dir;modify=20260102030405; docs\r\ntype=file;size=%d;modify=20260102030405; file.txt\r\n", len(server.body))
						case "LIST":
							fmt.Fprintf(transfer, "drwxr-xr-x 2 root root 4096 Jan 02 2026 docs\r\n-rw-r--r-- 1 root root %d Jan 02 2026 file.txt\r\n", len(server.body))
						case "RETR":
							io.WriteString(transfer, server.body)
						}
						transfer.Close()
						reply(226, "Transfer complete")
					case "QUIT":
						reply(221, "Bye")
						return
					default:
						reply(502, "Unsupported")
					}
				}
			}(control)
		}
	}()
	return server
}
func TestBrowseAndTransfer(t *testing.T) {
	for _, mode := range []string{"ftp", "explicit", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			s := fakeFTP(t, mode, true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			d, err := Browse(ctx, s.options, "")
			if err != nil {
				t.Fatal(err)
			}
			if d.Path != "/" || len(d.Entries) != 2 || !d.Entries[0].Directory || d.Entries[1].Name != "file.txt" {
				t.Fatalf("directory=%+v", d)
			}
			d, err = Browse(ctx, s.options, "/docs")
			if err != nil || d.Path != "/docs" {
				t.Fatalf("directory=%+v err=%v", d, err)
			}
			if _, err = Browse(ctx, s.options, "/denied"); err == nil {
				t.Fatal("access denial hidden")
			}
			var preview bytes.Buffer
			n, err := Read(ctx, s.options, "/file.txt", &preview, 65536)
			if err != nil || n != 65536 || preview.String() != s.body[:65536] {
				t.Fatalf("preview bytes=%d err=%v", n, err)
			}
			destination, err := Download(ctx, s.options, "/file.txt", t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(destination)
			if err != nil || string(data) != s.body {
				t.Fatalf("download err=%v bytes=%d", err, len(data))
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, command := range s.commands {
				switch command {
				case "STOR", "DELE", "MKD", "RMD", "RNFR", "RNTO":
					t.Fatalf("unexpected mutation: %s", command)
				}
			}
		})
	}
}
func TestFTPLoginAndCertificateFailures(t *testing.T) {
	s := fakeFTP(t, "ftp", false)
	bad := s.options
	bad.Password = "wrong"
	if _, err := Browse(context.Background(), bad, ""); err == nil || !AuthenticationRejected(err) {
		t.Fatalf("wrong password=%v", err)
	}
	anonymous := s.options
	anonymous.Username = "anonymous"
	anonymous.Password = "anonymous@"
	if _, err := Browse(context.Background(), anonymous, ""); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"explicit", "implicit"} {
		tlsServer := fakeFTP(t, mode, true)
		o := tlsServer.options
		o.Insecure = false
		if _, err := Browse(context.Background(), o, ""); err == nil {
			t.Fatal("untrusted certificate accepted")
		}
	}
}
func TestFTPCancellationAndInjection(t *testing.T) {
	s := fakeFTP(t, "ftp", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	if _, err := Download(ctx, s.options, "/file.txt", dir, nil); err == nil {
		t.Fatal("canceled download succeeded")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("partial download retained")
	}
	for _, remote := range []string{"/file\r\nDELE x", "/bad\x00file"} {
		if _, err := Browse(context.Background(), s.options, remote); err == nil {
			t.Fatal("injection accepted")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "file.txt")); !os.IsNotExist(err) {
		t.Fatalf("unexpected file %v", err)
	}
}

// Keep test command fixtures easy to inspect; data ports must remain on the
// control peer even when PASV advertises an unrelated address.
func TestPASVUsesControlPeer(t *testing.T) {
	s := fakeFTP(t, "ftp", false)
	// The fixture rejects EPSV so the client must fall back to PASV.
	d, err := Browse(context.Background(), s.options, "")
	if err != nil || len(d.Entries) != 2 {
		t.Fatalf("directory=%+v err=%v", d, err)
	}
}

func TestFTPCancellationInterruptsActiveLogin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	started := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "220 FTP fixture\r\n")
		_, err = bufio.NewReader(c).ReadString('\n')
		if err == nil {
			close(started)
		}
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Browse(ctx, Options{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Mode: "ftp", Username: "root", Password: "root", Timeout: time.Minute}, "")
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("login did not begin")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled login succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt socket read")
	}
}
