package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

// localVulnScripts selects the exact NSE category, never YAML tags or filenames.
// Catalog.Load uses installed files only when LibraryDir is set.
func (m model) localVulnScripts(ctx context.Context) (ids, skipped []string, err error) {
	if m.cat == nil || m.cat.LibraryDir() == "" {
		return nil, nil, fmt.Errorf("нужна установленная локальная библиотека NSE")
	}
	data, err := os.ReadFile(filepath.Join(m.cat.LibraryDir(), "categories.json"))
	if err != nil {
		return nil, nil, err
	}
	var index struct {
		Version int
		Entries map[string]struct {
			Kind       string
			Categories []string `json:"nse_categories"`
		}
	}
	if err = json.Unmarshal(data, &index); err != nil {
		return nil, nil, err
	}
	if index.Version != 1 || index.Entries == nil {
		return nil, nil, fmt.Errorf("некорректный локальный индекс категорий")
	}
	var candidates []string
	for path, e := range index.Entries {
		if e.Kind != "nse" || !strings.HasPrefix(path, "nmap/scripts/") || !strings.HasSuffix(path, ".nse") {
			continue
		}
		for _, category := range e.Categories {
			if category == "vuln" {
				candidates = append(candidates, path)
				break
			}
		}
	}
	sort.Strings(candidates)
	for _, id := range candidates {
		if err = ctx.Err(); err != nil {
			return nil, skipped, err
		}
		categories := index.Entries[id].Categories
		hasCategory := func(want string) bool {
			for _, category := range categories {
				if category == want {
					return true
				}
			}
			return false
		}
		if hasCategory("dos") || nseDenialOfServiceScript(m.entries, id) {
			skipped = append(skipped, id+": DoS-проверки отключены")
			continue
		}
		if !m.current.AllowExploit && (hasCategory("exploit") || hasCategory("intrusive") || nseRequiresOptInScript(m.entries, id)) {
			skipped = append(skipped, id+": интенсивная проверка отключена настройками проекта")
			continue
		}
		source, e := m.cat.Load(ctx, id)
		if e != nil {
			skipped = append(skipped, id+": "+e.Error())
			continue
		}
		if ok, reason := catalog.CheckWithLibrary(source, id, m.cat.LibraryDir()); !ok {
			skipped = append(skipped, id+": несовместимо с нашим NSE-движком: "+reason)
			continue
		}
		ids = append(ids, id)
	}
	return ids, skipped, nil
}

func (m model) openNSEVuln() (tea.Model, tea.Cmd) {
	services := m.savedVersionServices()
	if len(services) == 0 {
		m.message = "Нет сохранённых сервисов для активных vuln-проверок"
		return m, nil
	}
	if m.current.ID == 0 || m.store == nil || m.cat == nil || m.cat.LibraryDir() == "" {
		m.message = "Нужны открытый проект и локальная библиотека NSE"
		return m, nil
	}
	worker := m
	worker.entries = append([]catalog.Entry(nil), m.entries...)
	m.launch("nse-vuln", "NSE --script vuln — активные проверки", m.interactionHosts(), func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		return worker.runNSEVuln(ctx, services, emit)
	})
	j := m.jobs[len(m.jobs)-1]
	j.scope = "Все сохранённые сервисы проекта"
	j.options = []string{"Активные сетевые запросы; только NSE-категория vuln", "Без поиска хостов и портов; DoS отключён", fmt.Sprintf("Интенсивные проверки разрешены настройками проекта: %t", m.current.AllowExploit)}
	m.initJobLog(j)
	m.screen = "jobs"
	m.jobIndex = len(m.jobs) - 1
	m.message = "Запущены активные NSE vuln-проверки по сохранённым сервисам"
	return m, nil
}

func (m model) runNSEVuln(ctx context.Context, services []domain.Service, emit progressReporter) (result engine.Result, err error) {
	// Refresh metadata locally so DoS/impact restrictions do not depend on whether
	// the operator has opened the catalog screen in this session.
	m.entries, err = m.cat.List()
	if err != nil {
		return result, err
	}
	ids, skipped, err := m.localVulnScripts(ctx)
	result.Skipped = skipped
	if err != nil {
		return result, err
	}
	for _, reason := range skipped {
		emit("NSE vuln — пропущено: " + reason)
	}
	if len(ids) == 0 {
		return result, fmt.Errorf("нет доступных NSE vuln-проверок с текущими настройками; пропущено: %d", len(skipped))
	}
	emit(fmt.Sprintf("NSE vuln: выбрано %d скриптов; сервисов %d; пропущено %d", len(ids), len(services), len(skipped)))
	runID, err := m.store.StartRun(ctx, m.current.ID)
	if err != nil {
		return result, err
	}
	result.RunID = runID
	defer func() {
		status := "completed"
		if err != nil {
			status = "failed"
		}
		if ctx.Err() != nil {
			status = "cancelled"
		}
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e := m.store.FinishRun(finishCtx, runID, status)
		if err == nil {
			err = e
		}
	}()
	for _, s := range services {
		if err = m.store.SaveService(ctx, runID, s); err != nil {
			return result, err
		}
		result.Services = append(result.Services, s)
	}
	fs, errs := m.runNmapScriptsForServices(ctx, services, ids, func(stage string, _ ...int) { emit(stage) })
	result.Errors = append(result.Errors, errs...)
	for _, f := range fs {
		if err = m.store.SaveFinding(ctx, runID, f); err != nil {
			return result, err
		}
		result.Findings = append(result.Findings, f)
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	emit("NSE vuln завершено", len(services), len(services))
	return result, nil
}
