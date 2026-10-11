package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"path/filepath"
	"sort"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
	"wscan/internal/versionaudit"
)

func (m model) savedVersionServices() []domain.Service {
	byKey := map[string]domain.Service{}
	for _, h := range m.inventory {
		for _, s := range h.services {
			s.CPE = append([]string(nil), s.CPE...)
			byKey[serviceKey(s)] = s
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]domain.Service, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}
func (m model) openVersionCVE() (tea.Model, tea.Cmd) {
	services := m.savedVersionServices()
	if len(services) == 0 {
		m.message = "Нет сохранённых сервисов для сверки CVE; сканирование не запускается"
		return m, nil
	}
	if m.current.ID == 0 || m.store == nil || m.cat == nil || m.cat.LibraryDir() == "" {
		m.message = "Для офлайн-сверки нужны открытый проект и установленная локальная библиотека"
		return m, nil
	}
	path := filepath.Join(m.cat.LibraryDir(), "products.json")
	store := m.store
	projectID := m.current.ID
	targets := m.interactionHosts()
	m.launch("version-cve", "CVE — сохранённые версии (без сети)", targets, func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		return runVersionCVE(ctx, store, projectID, path, services, emit)
	})
	j := m.jobs[len(m.jobs)-1]
	j.scope = "Все сохранённые сервисы проекта"
	j.options = []string{"Только локальный products.json; без сканирования и сетевых запросов"}
	m.initJobLog(j)
	m.screen = "jobs"
	m.jobIndex = len(m.jobs) - 1
	m.message = "Офлайн-сверка всех сохранённых сервисов проекта"
	return m, nil
}
func runVersionCVE(ctx context.Context, store *storage.Store, projectID int64, path string, services []domain.Service, emit progressReporter) (result engine.Result, err error) {
	db, err := versionaudit.Load(path)
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	runID, err := store.StartRun(ctx, projectID)
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
		finishErr := store.FinishRun(finishCtx, runID, status)
		if err == nil {
			err = finishErr
		}
	}()
	for i, s := range services {
		if emit != nil {
			emit(fmt.Sprintf("Офлайн CVE: %d локальных правил; пропущено диапазонов: %d", db.Rules, db.Ignored), i, len(services))
		}
		fs, e := db.Assess(ctx, s)
		if e != nil {
			return result, e
		}
		// Save the input snapshot with the result, preserving the original fingerprint.
		if err = store.SaveService(ctx, runID, s); err != nil {
			return result, err
		}
		result.Services = append(result.Services, s)
		for _, f := range fs {
			if err = store.SaveFinding(ctx, runID, f); err != nil {
				return result, err
			}
			result.Findings = append(result.Findings, f)
		}
	}
	if emit != nil {
		emit("Сверка завершена, сетевых запросов: 0", len(services), len(services))
	}
	return result, nil
}
