package js

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPythonFileServerSnapshotAndCleanup(t *testing.T) {
	if _, e := python3Command(context.Background()); e != nil {
		t.Skip(e)
	}
	file := filepath.Join(t.TempDir(), "tool.exe")
	content := []byte{0, 1, 2, 255, 13, 10}
	if e := os.WriteFile(file, content, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, e := StartPythonFileServer(ctx, file, "127.0.0.1", 0)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	os.WriteFile(file, []byte("changed"), 0600)
	client := &http.Client{Timeout: time.Second}
	resp, e := client.Get(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || string(got) != string(content) {
		t.Fatal("snapshot changed")
	}
	hash := sha256.Sum256(content)
	if s.SHA256 != fmt.Sprintf("%x", hash) {
		t.Fatal("hash mismatch")
	}
	cancel()
	s.Close()
	s.Close()
	if _, e = os.Stat(s.dir); !os.IsNotExist(e) {
		t.Fatal("temporary directory retained")
	}
	if resp, e = client.Get(s.URL); e == nil {
		resp.Body.Close()
		t.Fatal("server still running")
	}
}
func TestPythonFileServerRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		file, ip string
		port     int
	}{{"missing", "bad", 8000}, {"missing", "127.0.0.1", 65536}, {t.TempDir(), "127.0.0.1", 8000}} {
		if s, e := StartPythonFileServer(context.Background(), tc.file, tc.ip, tc.port); e == nil {
			s.Close()
			t.Fatal("invalid input accepted")
		}
	}
}
