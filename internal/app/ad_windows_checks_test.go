package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wscan/internal/adscan"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	enginejs "wscan/internal/engine/js"
)

func TestADWindowsChecksServiceSelectionAndActiveGate(t *testing.T) {
	hosts := []adscan.Host{
		{Address: "10.0.0.1", Ports: []int{80, 53}},
		{Address: "10.0.0.2", Ports: []int{445, 3389, 135}},
		{Address: "10.0.0.3", Ports: []int{135}, DCConfirmed: true},
	}
	for _, active := range []bool{false, true} {
		var calls []string
		r := runADWindowsPlan(context.Background(), hosts, active, nil, func(_ context.Context, h adscan.Host, c adWindowsCheck) (bool, error) {
			calls = append(calls, h.Address+"/"+c.id)
			return true, nil
		})
		want := 4
		if active {
			want = 7
		}
		if len(calls) != want || len(r.Findings) != want {
			t.Fatalf("active=%v calls=%v findings=%v", active, calls, r.Findings)
		}
		if strings.Contains(strings.Join(calls, ","), "10.0.0.1/") || strings.Contains(strings.Join(calls, ","), "10.0.0.2/zerologon") {
			t.Fatal("unrelated service or unconfirmed DC was probed")
		}
		if !active && (len(r.Skipped) != 4 || !strings.Contains(strings.Join(r.Skipped, " "), "обрушить службу")) {
			t.Fatalf("active-check skips lost: %+v", r)
		}
		for _, f := range r.Findings {
			if f.Severity != "critical" || !strings.Contains(f.Target, ":") || f.MatchedAt != "tcp://"+f.Target {
				t.Fatalf("invalid vulnerability endpoint: %+v", f)
			}
		}
	}
}

func TestADWindowsChecksPreserveErrorsNLAAndPositiveCleanup(t *testing.T) {
	h := adscan.Host{Address: "10.0.0.2", Ports: []int{3389}}
	r := runADWindowsPlan(context.Background(), []adscan.Host{h}, false, nil, func(_ context.Context, _ adscan.Host, c adWindowsCheck) (bool, error) {
		if c.id == "ms12-020" {
			return true, fmt.Errorf("cleanup failed")
		}
		return false, enginejs.ErrRDPNLARequired
	})
	if len(r.Findings) != 1 || len(r.Errors) != 1 || len(r.Skipped) != 1 {
		t.Fatalf("lost independent results: %+v", r)
	}
	summary := adReconSummary(h.Address, adscan.Result{Hosts: []adscan.Host{h}, Diagnostics: append(r.Errors, r.Skipped...)}, r.Findings)
	for _, text := range []string{"риск-находки: 1", "Высший приоритет", "cleanup failed", "NLA"} {
		if !strings.Contains(summary.Evidence, text) {
			t.Fatalf("summary lacks %s: %s", text, summary.Evidence)
		}
	}
	r = runADWindowsPlan(context.Background(), []adscan.Host{h}, false, nil, func(context.Context, adscan.Host, adWindowsCheck) (bool, error) { return false, fmt.Errorf("timeout") })
	if len(r.Findings) != 0 || len(r.Errors) != 2 {
		t.Fatal("timeout produced a vulnerability or lost a diagnostic")
	}
}

func TestADWindowsChecksCancellationAndSMBGhostGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := runADWindowsPlan(ctx, []adscan.Host{{Address: "127.0.0.1", Ports: []int{445}}}, true, nil, func(context.Context, adscan.Host, adWindowsCheck) (bool, error) {
		t.Fatal("cancelled check started")
		return false, nil
	})
	if len(r.Findings) != 0 {
		t.Fatal("cancelled check produced findings")
	}
	w := Worker{current: domain.Project{AllowExploit: false}}
	if v, err := w.probeADSMBGhost(context.Background(), adscan.Host{Address: "127.0.0.1"}); v || err == nil {
		t.Fatal("SMBGhost bypassed project opt-in")
	}
}

func TestADDCComputerName(t *testing.T) {
	for input, want := range map[string]string{"dc01.customer.local.": "DC01", "DC01": "DC01", "10.0.0.1": "", "": "", "dc01/path": "", "too-long-netbios-name.domain": ""} {
		if got := adDCComputerName(input); got != want {
			t.Errorf("%q = %q, want %q", input, got, want)
		}
	}
}

func TestADSMBGhostLoadsLocalTemplateAndReportsMissingLibrary(t *testing.T) {
	w := Worker{cat: catalog.NewWithLibrary(t.TempDir(), t.TempDir()), current: domain.Project{AllowExploit: true}}
	if v, err := w.probeADSMBGhost(context.Background(), adscan.Host{Address: "127.0.0.1"}); v || err == nil {
		t.Fatal("missing template was treated as a completed negative check")
	}
	library := filepath.Join("..", "..", "library")
	if _, err := os.Stat(filepath.Join(library, "nuclei-templates", adSMBGhostTemplate)); err != nil {
		t.Skip("local scanner library not installed")
	}
	w.cat = catalog.NewWithLibrary(t.TempDir(), library)
	templates, errs := w.compileTemplates(context.Background(), []string{adSMBGhostTemplate})
	if len(errs) != 0 || len(templates) != 1 || templates[0].ID != "CVE-2020-0796" {
		t.Fatalf("SMBGhost template integration: %v %+v", errs, templates)
	}
}
