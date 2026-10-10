package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"net"
	"strconv"
	"strings"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type lfiState struct {
	target     domain.Service
	options    engine.LFIOptions
	busy       bool
	generation int
	cancel     context.CancelFunc
	output     string
}
type lfiDone struct {
	generation int
	result     *engine.LFIResult
	err        error
}

func (m model) openLFISetup() (tea.Model, tea.Cmd) {
	b := &m.lfiAudit
	if b.cancel != nil {
		b.cancel()
	}
	generation := b.generation + 1
	services := m.servicesFor(m.currentHost())
	target := domain.Service{Host: m.smbBrowser.host, Port: 80, Protocol: "tcp", Name: "http"}
	for i, s := range services {
		if strings.Contains(strings.ToLower(s.Name+" "+s.PortService), "http") {
			target = s
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	scheme := "http"
	if target.Tunnel == "ssl" || strings.Contains(strings.ToLower(target.Name), "https") || target.Port == 443 {
		scheme = "https"
	}
	*b = lfiState{generation: generation, target: target, options: engine.LFIOptions{URL: scheme + "://" + net.JoinHostPort(target.Host, strconv.Itoa(target.Port)) + "/?page=index.php", Parameter: "page"}}
	m.screen = "lfi-audit"
	m.message = ""
	return m, nil
}
func (m model) updateLFI(key string) (tea.Model, tea.Cmd) {
	b := &m.lfiAudit
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.busy = false
			m.message = "LFI отменена"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = "interaction-menu"
	case "u":
		m.startInput("lfi-url")
		m.input = b.options.URL
	case "p":
		m.startInput("lfi-parameter")
		m.input = b.options.Parameter
	case "v":
		m.startInput("lfi-vhost")
		m.input = b.options.VirtualHost
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "enter":
		return m.startLFI()
	}
	return m, nil
}
func (m model) startLFI() (tea.Model, tea.Cmd) {
	b := &m.lfiAudit
	if !m.current.AllowExploit {
		m.message = "Проверка чтения через LFI требует AllowExploit"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.generation++
	b.busy = true
	b.output = ""
	snapshot := *b
	store, project := m.store, m.current
	return m, func() tea.Msg {
		defer cancel()
		result, err := engine.CheckLFI(ctx, snapshot.target, snapshot.options)
		if err == nil && result != nil && result.Matched != nil && *result.Matched {
			runID, saveErr := store.StartRun(ctx, project.ID)
			if saveErr == nil {
				saveErr = store.SaveFinding(ctx, runID, domain.Finding{TemplateID: "native/web-lfi", Name: "Web: подтверждено чтение файла через Path Traversal / LFI", Severity: "medium", Target: net.JoinHostPort(snapshot.target.Host, strconv.Itoa(snapshot.target.Port)), MatchedAt: result.URL, Evidence: result.Evidence + "; параметр=" + result.Parameter + "; virtual host=" + snapshot.options.VirtualHost, Risk: "active", Time: time.Now().UTC()})
				status := "completed"
				if saveErr != nil {
					status = "failed"
				}
				finishCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				finishErr := store.FinishRun(finishCtx, runID, status)
				stop()
				if saveErr == nil {
					saveErr = finishErr
				}
			}
			if saveErr != nil {
				err = fmt.Errorf("результат получен, но сохранение не завершено: %w", saveErr)
			}
		}
		return lfiDone{snapshot.generation, result, err}
	}
}
func (m model) applyLFIDone(done lfiDone) (tea.Model, tea.Cmd) {
	b := &m.lfiAudit
	if done.generation != b.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.err != nil {
		m.message = "LFI: " + smbDisplayName(done.err.Error())
	}
	if done.result != nil {
		r := done.result
		status := "неопределено"
		if r.Matched != nil {
			status = "не подтверждено"
			if *r.Matched {
				status = "подтверждено"
			}
		}
		b.output = fmt.Sprintf("Результат: %s · запросов: %d\n%s\n%s", status, r.Requests, r.Evidence, r.Limitation)
	}
	return m, nil
}
func (m model) viewLFI(w int) string {
	b := m.lfiAudit
	body := headingStyle.Render("Web — Path Traversal / LFI") + fmt.Sprintf("\nСервис: %s:%d\nURL: %s\nПараметр: %s\nVirtual host: %s\nПроверка TLS: %t\n\nu URL · p параметр · v virtual host · t TLS · Enter проверить\nМаксимум 4 запроса; без редиректов и UNC/OAST.\n\n%s", b.target.Host, b.target.Port, smbDisplayName(b.options.URL), smbDisplayName(b.options.Parameter), smbDisplayName(b.options.VirtualHost), !b.options.Insecure, b.output)
	if b.busy {
		body += "\nВыполняется… Esc отменить"
	}
	return m.renderPanel(w, body)
}
