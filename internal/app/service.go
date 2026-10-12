package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/catalog"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

type Service struct {
	Store     *storage.Store
	Catalog   *catalog.Catalog
	Scanner   *engine.Engine
	Jobs      *Manager
	entriesMu sync.Mutex
	entries   []catalog.Entry
}

func NewService(ctx context.Context, s *storage.Store, c *catalog.Catalog, e *engine.Engine) (*Service, error) {
	m, err := NewManager(ctx, s)
	if err != nil {
		return nil, err
	}
	return &Service{Store: s, Catalog: c, Scanner: e, Jobs: m}, nil
}
func (s *Service) Close() { s.Jobs.Close() }
func (s *Service) Project(ctx context.Context, id int64) (domain.Project, error) {
	ps, err := s.Store.ListProjects(ctx)
	if err != nil {
		return domain.Project{}, err
	}
	for _, p := range ps {
		if p.ID == id {
			return p, nil
		}
	}
	return domain.Project{}, fmt.Errorf("проект не найден")
}
func (s *Service) Entries() ([]catalog.Entry, error) {
	s.entriesMu.Lock()
	defer s.entriesMu.Unlock()
	if s.entries == nil {
		entries, err := s.Catalog.List()
		if err != nil {
			return nil, err
		}
		s.entries = entries
	}
	return append([]catalog.Entry(nil), s.entries...), nil
}
func (s *Service) InvalidateCatalog() { s.entriesMu.Lock(); s.entries = nil; s.entriesMu.Unlock() }

type ScanRequest struct {
	ProjectID  int64             `json:"project_id"`
	Spec       Spec              `json:"spec"`
	CIDR       string            `json:"cidr,omitempty"`
	NewProject bool              `json:"new_project,omitempty"`
	DNS        adscan.DNSOptions `json:"dns,omitempty"`
}

func (s *Service) StartScan(ctx context.Context, r ScanRequest, source, key string) (Job, error) {
	var p domain.Project
	var err error
	if r.ProjectID != 0 {
		p, err = s.Project(ctx, r.ProjectID)
		if err != nil {
			return Job{}, err
		}
	} else if r.Spec.Kind != "ad-scan" {
		return Job{}, fmt.Errorf("выберите проект")
	}
	if r.Spec.Kind == "ad-scan" {
		if len(r.Spec.Hosts) == 0 {
			r.Spec.Hosts = strings.Fields(r.CIDR)
		}
		if len(r.Spec.Hosts) == 0 {
			r.Spec.Hosts = append([]string(nil), p.Targets...)
		}
		if err := adscan.ValidateTargets(r.Spec.Hosts); err != nil {
			return Job{}, err
		}
		r.CIDR = strings.Join(r.Spec.Hosts, " ")
		if _, err := adscan.ValidateDNSOptions(r.DNS); err != nil {
			return Job{}, err
		}
		r.Spec.TemplateIDs = nil
	} else {
		switch r.Spec.Kind {
		case "discover", "checks", "full", "port", "bulk-port", "alive-hosts", "ptr":
		default:
			return Job{}, fmt.Errorf("неизвестный профиль")
		}
		if len(r.Spec.Hosts) == 0 {
			r.Spec.Hosts = append([]string(nil), p.Targets...)
		}
		if len(r.Spec.Hosts) == 0 {
			return Job{}, fmt.Errorf("укажите область проверки")
		}
		for _, target := range r.Spec.Hosts {
			if err := discovery.ValidateTarget(target); err != nil {
				return Job{}, err
			}
		}
		for _, port := range append(append([]int(nil), r.Spec.DiscPorts...), r.Spec.DiscUDPPorts...) {
			if port < 1 || port > 65535 {
				return Job{}, fmt.Errorf("порт должен быть 1–65535")
			}
		}
		if r.Spec.Kind == "full" {
			p.DiscoveryEnabled = true
		}
	}
	var entries []catalog.Entry
	if r.Spec.Kind == "checks" || r.Spec.Kind == "full" || r.Spec.Kind == "port" || r.Spec.Kind == "bulk-port" {
		entries, err = s.Entries()
		if err != nil {
			return Job{}, err
		}
	}
	if r.Spec.Kind == "checks" && len(r.Spec.TemplateIDs) == 0 {
		r.Spec.TemplateIDs = append([]string(nil), p.TemplateIDs...)
	}
	if r.Spec.Kind == "checks" && len(r.Spec.TemplateIDs) == 0 {
		return Job{}, fmt.Errorf("проверки не выбраны: откройте обзор → Выбрать проверки")
	}
	if r.Spec.Kind == "full" {
		if len(r.Spec.TemplateIDs) > 0 {
			p.TemplateIDs = append([]string(nil), r.Spec.TemplateIDs...)
		}
		r.Spec.TemplateIDs = append([]string(nil), p.TemplateIDs...)
	}
	if len(r.Spec.TemplateIDs) > 0 {
		known := map[string]bool{}
		for _, e := range entries {
			known[e.Path] = true
		}
		for _, id := range r.Spec.TemplateIDs {
			if !known[id] {
				return Job{}, fmt.Errorf("проверка %q отсутствует в каталоге", id)
			}
		}
	}
	inventory, err := s.Inventory(ctx, p.ID)
	if err != nil {
		return Job{}, err
	}
	if r.Spec.Kind == "port" || r.Spec.Kind == "bulk-port" {
		wanted := r.Spec.Services
		if r.Spec.Service != nil {
			wanted = []domain.Service{*r.Spec.Service}
		}
		if len(wanted) == 0 {
			return Job{}, fmt.Errorf("выберите известный сервис")
		}
		var verified []domain.Service
		for _, w := range wanted {
			found := false
			for _, v := range inventory.Services {
				if w.Host == v.Host && w.Port == v.Port && w.Protocol == v.Protocol {
					verified = append(verified, v)
					found = true
					break
				}
			}
			if !found {
				return Job{}, fmt.Errorf("сервис отсутствует в инвентаризации проекта")
			}
		}
		r.Spec.Services = verified
		if r.Spec.Kind == "port" {
			r.Spec.Service = &verified[0]
		}
	}
	if r.Spec.Label == "" {
		r.Spec.Label = operationLabel(r.Spec.Kind)
	}
	worker := NewWorker(s.Store, s.Catalog, s.Scanner, p, entries, inventory.Services, r.NewProject, r.DNS)
	if r.Spec.Kind == "checks" && len(worker.knownServices(r.Spec.Hosts)) == 0 {
		return Job{}, fmt.Errorf("нет известных сервисов: сначала запустите Поиск портов и сервисов")
	}
	req := JobRequest{ProjectID: p.ID, Kind: r.Spec.Kind, Label: r.Spec.Label, Targets: append([]string(nil), r.Spec.Hosts...), Scope: strings.Join(r.Spec.Hosts, ", "), Source: source, Checks: r.Spec.TemplateIDs}
	if key != "" {
		raw, _ := json.Marshal(r)
		req.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(raw))
		key = fmt.Sprintf("scan:%s:%s", source, key)
	}
	execute := func(ctx context.Context, emit Reporter) (Outcome, error) {
		if r.Spec.Kind == "ad-scan" {
			res, details, id, name, err := worker.RunADScan(ctx, r.CIDR, emit)
			return Outcome{Result: res, AD: details, ProjectID: id, ProjectName: name}, err
		}
		res, err := worker.Build(r.Spec)(ctx, emit)
		for _, host := range res.LiveHosts {
			if saveErr := s.Store.AddTarget(context.Background(), p.ID, host); saveErr != nil {
				res.Errors = append(res.Errors, saveErr.Error())
			}
		}
		return Outcome{Result: res, ProjectID: p.ID, ProjectName: p.Name}, err
	}
	return s.Jobs.Start(req, key, execute)
}
func operationLabel(kind string) string {
	switch kind {
	case "ad-scan":
		return "Аудит AD"
	case "discover":
		return "Поиск портов и сервисов"
	case "checks":
		return "Выбранные проверки"
	case "full":
		return "Обнаружение и проверки"
	case "alive-hosts":
		return "Поиск живых хостов"
	case "ptr":
		return "DNS PTR"
	default:
		return "Проверка сервиса"
	}
}

type Inventory struct {
	Services []domain.Service `json:"services"`
	Findings []domain.Finding `json:"findings"`
	Runs     []domain.Run     `json:"runs"`
}

func (s *Service) Inventory(ctx context.Context, projectID int64) (Inventory, error) {
	out := Inventory{Services: []domain.Service{}, Findings: []domain.Finding{}, Runs: []domain.Run{}}
	if projectID == 0 {
		return out, nil
	}
	runs, err := s.Store.Runs(ctx, projectID)
	if err != nil {
		return out, err
	}
	out.Runs = runs
	exclusions, err := s.Store.InventoryExclusions(ctx, projectID)
	if err != nil {
		return out, err
	}
	resets, err := s.Store.InventoryResets(ctx, projectID)
	if err != nil {
		return out, err
	}
	reset := map[string]int64{}
	excluded := map[string]bool{}
	for _, r := range resets {
		reset[r.Host] = r.ThroughRun
		for _, a := range r.Aliases {
			reset[a] = r.ThroughRun
		}
	}
	for _, e := range exclusions {
		excluded[e.Host+"|"+e.ServiceKey] = true
	}
	seen := map[string]bool{}
	for _, run := range runs {
		services, err := s.Store.Services(ctx, run.ID)
		if err != nil {
			return out, err
		}
		for _, v := range services {
			host := serviceHostBucket(v, nil)
			key := fmt.Sprintf("%s/%s/%d", v.Host, v.Protocol, v.Port)
			if run.ID <= max(reset[host], reset[v.Host]) || excluded[host+"|"] || excluded[v.Host+"|"] || excluded[host+"|"+key] || excluded[v.Host+"|"+key] {
				continue
			}
			identity := fmt.Sprintf("%s|%s|%s", host, v.Host, key)
			if !seen[identity] {
				seen[identity] = true
				out.Services = append(out.Services, v)
			}
		}
		fs, err := s.Store.Findings(ctx, run.ID)
		if err != nil {
			return out, err
		}
		for _, f := range fs {
			host := findingHost(f)
			if !excluded[host+"|"] && (reset[host] == 0 || run.ID > reset[host]) {
				out.Findings = append(out.Findings, f)
			}
		}
	}
	sort.Slice(out.Services, func(i, j int) bool {
		a, b := out.Services[i], out.Services[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})
	return out, nil
}
func (s *Service) CreateProject(ctx context.Context, name string, targets []string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return 0, fmt.Errorf("название проекта: 1–200 символов")
	}
	for _, t := range targets {
		if err := discovery.ValidateTarget(t); err != nil {
			return 0, err
		}
	}
	return s.Store.CreateProjectWithTargets(ctx, name, uniqueStrings(targets))
}
func (s *Service) DeleteProject(ctx context.Context, id int64) error {
	if s.Jobs.Active(id) {
		return fmt.Errorf("сначала остановите задачи проекта")
	}
	return s.Store.DeleteProject(ctx, id)
}
func (s *Service) SaveSettings(ctx context.Context, p domain.Project) error {
	if _, err := s.Project(ctx, p.ID); err != nil {
		return err
	}
	if p.RPS < 0 || p.RPS > 10000 || p.Concurrency < 1 || p.Concurrency > 256 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 300 || p.Retries < 0 || p.Retries > 10 || p.DiscoveryRPS < 0 || p.DiscoveryRPS > 100000 || p.DiscoveryConcurrency < 1 || p.DiscoveryConcurrency > 2048 || p.LockoutMaxAttempts < 1 || p.LockoutMaxAttempts > 100 || p.LockoutWindowMinutes < 1 || p.LockoutWindowMinutes > 1440 {
		return fmt.Errorf("некорректные лимиты проекта")
	}
	return s.Store.SetProjectScanSettings(ctx, p)
}
func (s *Service) StartModule(ctx context.Context, projectID, credentialID int64, target domain.Service, name string, args map[string]string, source, key string) (Job, error) {
	p, err := s.Project(ctx, projectID)
	if err != nil {
		return Job{}, err
	}
	if !p.AllowCredentialAttack {
		return Job{}, fmt.Errorf("проверки учёток отключены в проекте")
	}
	if name == "winrm-exec" && !p.AllowExploit {
		return Job{}, fmt.Errorf("выполнение команд требует AllowExploit")
	}
	creds, err := s.Store.ListCredentials(ctx, projectID)
	if err != nil {
		return Job{}, err
	}
	var cred *domain.Credential
	for i := range creds {
		if creds[i].ID == credentialID {
			cred = &creds[i]
			break
		}
	}
	if cred == nil {
		return Job{}, fmt.Errorf("учётка не принадлежит проекту")
	}
	failures, err := s.Store.RecentFailureCount(ctx, projectID, cred.Username, time.Now().Add(-time.Duration(p.LockoutWindowMinutes)*time.Minute))
	if err != nil {
		return Job{}, err
	}
	if failures >= p.LockoutMaxAttempts {
		return Job{}, fmt.Errorf("достигнут лимит ошибок входа")
	}
	inventory, err := s.Inventory(ctx, projectID)
	if err != nil {
		return Job{}, err
	}
	found := false
	for _, v := range inventory.Services {
		if v.Host == target.Host && v.Port == target.Port && v.Protocol == target.Protocol {
			found = true
			break
		}
	}
	if !found {
		return Job{}, fmt.Errorf("выберите сервис из инвентаризации проекта")
	}
	req := JobRequest{ProjectID: projectID, Kind: "module", Label: name, Targets: []string{target.Host}, Scope: fmt.Sprintf("%s:%d · %s", target.Host, target.Port, name), Source: source}
	return s.Jobs.Start(req, key, func(ctx context.Context, emit Reporter) (Outcome, error) {
		emit("Выполняю " + name)
		output, err := s.Scanner.RunModule(ctx, p, target, *cred, name, args)
		runID, saveErr := s.Store.StartRun(ctx, projectID)
		if saveErr != nil {
			return Outcome{}, saveErr
		}
		res := engine.Result{RunID: runID}
		if output != nil {
			raw, _ := json.Marshal(output)
			f := domain.Finding{TemplateID: "module/" + name, Name: name, Target: target.Host, MatchedAt: fmt.Sprintf("%s:%d", target.Host, target.Port), Evidence: string(raw), Description: name, Severity: "info", Time: time.Now()}
			if e := s.Store.SaveFinding(ctx, runID, f); e != nil {
				err = e
			} else {
				res.Findings = []domain.Finding{f}
			}
		}
		status := "completed"
		if err != nil {
			status = "failed"
		}
		if ctx.Err() != nil {
			status = "cancelled"
		}
		_ = s.Store.FinishRun(context.Background(), runID, status)
		return Outcome{Result: res, ProjectID: projectID}, err
	})
}

func (s *Service) ValidateTargets(targets []string) ([]string, error) {
	for _, t := range targets {
		if err := discovery.ValidateTarget(t); err != nil {
			return nil, err
		}
	}
	return uniqueStrings(targets), nil
}

func findingHost(f domain.Finding) string {
	for _, v := range []string{f.MatchedAt, f.Target} {
		if strings.Contains(v, "://") {
			if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
				return u.Hostname()
			}
		}
		if h, _, err := net.SplitHostPort(v); err == nil {
			return h
		}
		if net.ParseIP(v) != nil {
			return v
		}
	}
	return f.Target
}
