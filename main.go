package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/libsync"
	"wscan/internal/nse"
	"wscan/internal/report"
	"wscan/internal/storage"
	tpl "wscan/internal/template"
	"wscan/internal/tui"
	"wscan/internal/workflow"
)

var version = "dev"

//go:embed docs/SUPPORTED.md
var supportedFeatures string

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h", "help":
			fmt.Println("wscan: scan, export, version, capabilities, library, signatures, audit-library, coerce, ad-scan, audit, local-smb\nRead-only audit: wscan audit --help\nAD discovery: wscan ad-scan --help\nLocal SMB accounts: wscan local-smb --help")
			return
		case "audit":
			fatalIf(runAuditCLI(os.Args[2:]))
			return
		case "ad-scan":
			fatalIf(runADScanCLI(os.Args[2:]))
			return
		case "local-smb":
			fatalIf(runLocalSMBCLI(os.Args[2:]))
			return
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "coerce" {
		fatalIf(runCoercionCLI(os.Args[2:]))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "signatures" {
		root, err := os.UserConfigDir()
		fatalIf(err)
		report := discovery.ServiceProbeReport(findLibraryDir(filepath.Join(root, "wscan")))
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		fatalIf(encoder.Encode(report))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "capabilities" {
		fmt.Print(supportedFeatures)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "audit-library" {
		output := "reports/library-audit"
		if len(os.Args) > 2 {
			output = os.Args[2]
		}
		root, err := os.UserConfigDir()
		fatalIf(err)
		fatalIf(catalog.NewWithLibrary("", findLibraryDir(filepath.Join(root, "wscan"))).Audit(output))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("wscan " + version)
		return
	}
	root, err := os.UserConfigDir()
	fatalIf(err)
	appDir := filepath.Join(root, "wscan")
	fatalIf(os.MkdirAll(appDir, 0o755))

	if len(os.Args) > 1 && os.Args[1] == "library" {
		fatalIf(runLibrary(appDir, os.Args[2:]))
		return
	}
	webEnabled, tuiWeb, webAddress, webErr := webMode(os.Args[1:])
	fatalIf(webErr)
	if len(os.Args) == 1 || webEnabled || os.Args[1] == "scan" {
		unlock, err := app.OwnerLock(appDir)
		fatalIf(err)
		defer unlock()
	}
	store, err := storage.Open(filepath.Join(appDir, "wscan.db"))
	fatalIf(err)
	defer store.Close()
	libraryDir := findLibraryDir(appDir)
	if libraryDir == "" && (len(os.Args) == 1 || os.Args[1] == "scan") {
		fmt.Fprintln(os.Stderr, "Скачивание библиотеки проверок из отдельного репозитория…")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		cfg, updateErr := libsync.UpdateContext(ctx, appDir, "", "")
		cancel()
		fatalIf(updateErr)
		libraryDir = cfg.Path
	}
	cat := catalog.NewWithLibrary(filepath.Join(appDir, "templates"), libraryDir)
	scan := engine.New(store, engine.Config{RPS: 5, Concurrency: 4, TimeoutSeconds: 10, Complete: false, OAST: true, LibraryDir: cat.LibraryDir()})
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		fatalIf(runScan(context.Background(), store, cat, scan, os.Args[2:]))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "export" {
		fatalIf(runExport(context.Background(), store, appDir, os.Args[2:]))
		return
	}
	if webEnabled {
		fatalIf(runWeb(store, cat, scan, appDir, tuiWeb, webAddress))
		return
	}
	fatalIf(tui.Run(context.Background(), store, cat, scan, appDir))
}

func runLibrary(appDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wscan library update [git-url] [--ref branch]")
	}
	switch args[0] {
	case "update":
		url, ref := "", ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--ref":
				i++
				if i >= len(args) {
					return fmt.Errorf("--ref needs a value")
				}
				ref = args[i]
			default:
				if strings.HasPrefix(args[i], "-") {
					return fmt.Errorf("unknown flag %s", args[i])
				}
				url = args[i]
			}
		}
		cfg, err := libsync.Update(appDir, url, ref)
		if err != nil {
			return err
		}
		fmt.Printf("Библиотека обновлена: %s\n  path: %s\n  ref: %s\n  commit: %s\n", cfg.URL, cfg.Path, cfg.Ref, cfg.Commit)
		return nil
	case "status":
		status, err := libsync.Inspect(appDir)
		cfg := status.Config
		if err != nil {
			return err
		}
		fmt.Printf("url: %s\nref: %s\npath: %s\ncommit: %s\nupdated_at: %s\ninstalled: %t\ntemplates: %d\nfiles: %d\nbytes: %d\n", cfg.URL, cfg.Ref, cfg.Path, cfg.Commit, cfg.UpdatedAt, status.Installed, status.Templates, status.Files, status.Bytes)
		return nil
	default:
		return fmt.Errorf("usage: wscan library update|status")
	}
}

// findLibraryDir prefers a synced copy under the app config dir, then nearby
// checkout (./library), then next to the binary.
func findLibraryDir(appDir string) string {
	var candidates []string
	if appDir != "" {
		candidates = append(candidates, libsync.DefaultDir(appDir))
		if cfg, err := libsync.LoadConfig(appDir); err == nil && cfg.Path != "" {
			candidates = append([]string{cfg.Path}, candidates...)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "library"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "library"))
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		if info, err := os.Stat(libsync.TemplateDir(candidate)); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func runScan(ctx context.Context, store *storage.Store, cat *catalog.Catalog, scan *engine.Engine, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wscan scan PROJECT_ID")
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid project id: %w", err)
	}
	projects, err := store.ListProjects(ctx)
	if err != nil {
		return err
	}
	var p domain.Project
	for _, candidate := range projects {
		if candidate.ID == id {
			p = candidate
			break
		}
	}
	if p.ID == 0 {
		return fmt.Errorf("project %d not found", id)
	}
	var templates []domain.Template
	var nseIDs []string
	var skipped []string
	for _, name := range p.TemplateIDs {
		b, e := cat.Load(ctx, name)
		if e != nil {
			skipped = append(skipped, name+": "+e.Error())
			continue
		}
		if strings.HasPrefix(name, "nmap/scripts/") {
			nseIDs = append(nseIDs, name)
			continue
		}
		t, e := tpl.ForExecution(b, name)
		if e != nil {
			skipped = append(skipped, name+": "+e.Error())
			continue
		}
		if !t.Compatible {
			reason := "unsupported template"
			if len(t.Unsupported) > 0 {
				reason = t.Unsupported[0]
			}
			skipped = append(skipped, name+": "+reason)
			continue
		}
		templates = append(templates, t)
	}
	if len(templates) == 0 && len(nseIDs) == 0 && !p.DiscoveryEnabled {
		return fmt.Errorf("project has no compatible cached templates; sync the catalog and select checks in the TUI")
	}
	discoverer := discovery.Scanner{Config: discovery.Config{LibraryDir: cat.LibraryDir(), RPS: p.DiscoveryRPS, Concurrency: p.DiscoveryConcurrency, AllPorts: p.AllPorts}}
	runner := workflow.Runner{Discovery: discoverer, HTTP: scan}
	result, err := runner.Run(ctx, p, templates)
	if err != nil {
		return err
	}
	if len(nseIDs) > 0 {
		findings, errs := runNSEScripts(ctx, cat.LibraryDir(), p, result.Services, nseIDs)
		result.Errors = append(result.Errors, errs...)
		for _, f := range findings {
			if saveErr := store.SaveFinding(ctx, result.RunID, f); saveErr != nil {
				result.Errors = append(result.Errors, "save nse result: "+saveErr.Error())
			} else {
				result.Findings = append(result.Findings, f)
			}
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintln(os.Stderr, "Skipped:", strings.Join(skipped, "; "))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"run_id": result.RunID, "services": result.Services, "targets_scanned": result.TargetsScanned, "http_requests_saved": result.HTTPRequestsSaved, "findings": result.Findings, "errors": result.Errors})
}

// runNSEScripts runs the selected NSE scripts against discovered services with
// the complete NSE engine, grouping services by address and their
// original scope entry so a domain target keeps its hostname.
func runNSEScripts(ctx context.Context, libraryDir string, p domain.Project, services []domain.Service, scriptIDs []string) ([]domain.Finding, []string) {
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	runner := nse.New(libraryDir, nse.Config{Timeout: timeout, RPS: p.RPS, Complete: false, Args: nse.DefaultBruteArgs(p.RPS, p.Concurrency)})
	groups := map[string][]domain.Service{}
	displays := map[string]string{}
	var order []string
	for _, s := range services {
		bucket := s.Target
		if bucket == "" {
			bucket = s.Host
		}
		display := bucket
		bucket += "\x00" + s.Host
		displays[bucket] = display
		if _, ok := groups[bucket]; !ok {
			order = append(order, bucket)
		}
		groups[bucket] = append(groups[bucket], s)
	}
	var findings []domain.Finding
	var errs []string
	for _, key := range order {
		svcs := groups[key]
		host := displays[key]
		name := ""
		if net.ParseIP(host) == nil {
			name = host
		}
		hi := nse.HostInfo{Name: name, IP: svcs[0].Host}
		var ports []nse.PortInfo
		for _, s := range svcs {
			ports = append(ports, nse.PortInfo{Number: s.Port, Protocol: s.Protocol, State: "open", Service: s.Name, Product: s.Product, Version: s.Version, Tunnel: s.Tunnel})
		}
		for _, id := range scriptIDs {
			path := filepath.Join(libraryDir, filepath.FromSlash(id))
			res, ran, err := runner.Run(ctx, path, hi, ports)
			if err != nil {
				errs = append(errs, err.Error())
			}
			if !ran {
				continue
			}
			for _, r := range res {
				if nse.OutputIsError(r.Output) {
					errs = append(errs, id+": "+r.Output)
					continue
				}
				if nse.OutputIsNoise(r.ScriptID, r.Output) {
					continue
				}
				target := host
				matched := "nse://" + host
				if r.Port != 0 {
					target = fmt.Sprintf("%s:%d", host, r.Port)
					matched = fmt.Sprintf("nse://%s:%d/%s", host, r.Port, r.ScriptID)
				}
				findings = append(findings, domain.Finding{TemplateID: "nmap/" + r.ScriptID, Name: r.ScriptID, Severity: nse.ScriptSeverity(r.ScriptID, r.Output), Target: target, MatchedAt: matched, Evidence: r.Output, Risk: "active", Time: time.Now().UTC()})
			}
		}
	}
	return findings, errs
}

func runExport(ctx context.Context, store *storage.Store, appDir string, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: wscan export PROJECT_ID RUN_ID json|html|csv OUTPUT_PATH")
	}
	pid, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return err
	}
	rid, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	projects, err := store.ListProjects(ctx)
	if err != nil {
		return err
	}
	var p domain.Project
	for _, x := range projects {
		if x.ID == pid {
			p = x
			break
		}
	}
	if p.ID == 0 {
		return fmt.Errorf("project %d not found", pid)
	}
	runs, err := store.Runs(ctx, pid)
	if err != nil {
		return err
	}
	var run *domain.Run
	for i := range runs {
		if runs[i].ID == rid {
			run = &runs[i]
			break
		}
	}
	if run == nil {
		return fmt.Errorf("run %d not found", rid)
	}
	path := args[3]
	if !filepath.IsAbs(path) {
		path = filepath.Join(appDir, "reports", path)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return report.Export(path, args[2], report.Data{Project: p.Name, Run: *run})
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "wscan:", err)
		os.Exit(1)
	}
}
