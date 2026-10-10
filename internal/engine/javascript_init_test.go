package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// fakeSSHKeyServer accepts only the given public key for any username and
// closes the session immediately after auth — enough to exercise
// ConnectWithKey's success path without needing a real shell.
func fakeSSHKeyServer(t *testing.T, acceptedKey ssh.PublicKey) int {
	t.Helper()
	hostKey, err := ssh.NewSignerFromKey(mustGenerateRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), acceptedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					_ = newChan.Reject(ssh.Prohibited, "no channels")
				}
			}(nConn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func loadUpstreamJSTemplate(t *testing.T, sub, name string) domain.Template {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library", "nuclei-templates", "javascript", sub),
		filepath.Join("library", "nuclei-templates", "javascript", sub),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			raw, err := os.ReadFile(filepath.Join(c, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			tm, err := tpl.ForExecution(raw, "javascript/"+sub+"/"+name)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if !tm.Compatible {
				t.Fatalf("%s not compatible: %v", name, tm.Unsupported)
			}
			return tm
		}
	}
	t.Fatalf("library/nuclei-templates/javascript/%s/%s not found", sub, name)
	return domain.Template{}
}

func libraryDirForTest(t *testing.T) string {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library"),
		"library",
	} {
		if st, err := os.Stat(filepath.Join(c, "nuclei-templates")); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("library/ not found")
	return ""
}

// TestCVE202334039InitUpdatePayloadReadsRealKeys reproduces "Ошибка проверки:
// CVE-2023-34039: javascript: GoError: ssh: no key found": the template's
// init: block reads every key in helpers/payloads/cve-2023-34039-keys via
// require('nuclei/fs').ReadFilesFromDir and feeds them back with
// updatePayload('keys', ...), replacing the dummy1/dummy2 placeholders.
// Runs the real, unmodified upstream template end to end against a fake SSH
// server that only accepts one specific real key from that directory.
func TestCVE202334039InitUpdatePayloadReadsRealKeys(t *testing.T) {
	libDir := libraryDirForTest(t)
	keyPath := filepath.Join(libDir, "nuclei-templates", "helpers", "payloads", "cve-2023-34039-keys", "id_rsa_vnera_keypair_6.0.0_platform")
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}

	port := fakeSSHKeyServer(t, signer.PublicKey())
	tmpl := loadUpstreamJSTemplate(t, "cves/2023", "CVE-2023-34039.yaml")
	tmpl = withJSPort(tmpl, port)

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 10, LibraryDir: libDir})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Logf("scan error (expected for the 21 non-matching keys): %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (the one accepted key), got %d errs=%v", len(res.Findings), res.Errors)
	}
}
