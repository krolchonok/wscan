package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wscan/internal/catalog"
	"wscan/internal/nse"
)

func TestNSETimeoutLogsScriptAndContinues(t *testing.T) {
	dir := t.TempDir()
	scripts := filepath.Join(dir, "nmap", "scripts")
	if err := os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"slow.nse": `hostrule=function() return true end; action=function() while true do end end`, "next.nse": `hostrule=function() return true end; action=function() return "next completed" end`} {
		if err := os.WriteFile(filepath.Join(scripts, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := model{cat: catalog.NewWithLibrary(dir, dir)}
	runner := nse.New(dir, nse.Config{ScriptTimeout: 50 * time.Millisecond})
	var logs []string
	findings, errs := m.runNmapScriptsOn(context.Background(), runner, "127.0.0.1", nse.HostInfo{IP: "127.0.0.1"}, nil, []string{"nmap/scripts/slow.nse", "nmap/scripts/next.nse"}, func(stage string, counts ...int) { logs = append(logs, stage) })
	if len(errs) != 1 || !strings.Contains(errs[0], "общий таймаут") {
		t.Fatalf("errors: %v", errs)
	}
	if len(findings) != 1 || findings[0].Evidence != "next completed" {
		t.Fatalf("findings: %v", findings)
	}
	for _, want := range []string{"slow.nse — запуск (лимит", "slow.nse — таймаут за", "next.nse — запуск", "next.nse — завершён за"} {
		if !strings.Contains(strings.Join(logs, "\n"), want) {
			t.Fatalf("missing %s: %v", want, logs)
		}
	}
}
