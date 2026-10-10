package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"wscan/internal/domain"
	"wscan/internal/nse"
)

// Regression guard: installing external scanners must never switch engines.
func TestNativeScansNeverLaunchExternalEngines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell executables need Unix")
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "external-engine-was-called")
	for _, name := range []string{"nuclei", "nmap", "msfconsole", "msfvenom"} {
		script := fmt.Sprintf("#!/bin/sh\necho called >> %q\nexit 97\n", marker)
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("native-result")) }))
	defer server.Close()
	result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}"}, Matchers: []domain.Matcher{{Type: "word", Words: []string{"native-result"}}}})
	if len(result.Findings) != 1 {
		t.Fatalf("native HTTP failed: %+v", result)
	}
	path := filepath.Join(directory, "native.nse")
	source := `portrule=function() return true end; action=function() return "native-nse-result" end`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	results, ran, err := nse.New("", nse.Config{Timeout: time.Second}).Run(context.Background(), path, nse.HostInfo{IP: "127.0.0.1"}, []nse.PortInfo{{Number: 8080, Protocol: "tcp", State: "open"}})
	if err != nil || !ran || len(results) != 1 || results[0].Output != "native-nse-result" {
		t.Fatalf("native NSE failed: %v %v %v", results, ran, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("external engine was invoked: %v", err)
	}
}
