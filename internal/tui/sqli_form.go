package tui

import (
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type sqliFormState struct {
	projectID                      int64
	options                        engine.SQLiFormOptions
	generation, index, done, total int
	errors, forms                  int
	busy                           bool
	cancel                         context.CancelFunc
	hits                           []engine.SQLiFormHit
	limitation                     string
	detail                         bool
}
type sqliFormEvent struct {
	generation int
	progress   engine.SQLiFormProgress
}
type sqliFormDelivery struct {
	event   sqliFormEvent
	channel <-chan sqliFormEvent
}
type sqliFormClosed struct{ generation int }
type sqliFormDone struct {
	generation int
	result     engine.SQLiFormResult
	err        error
}

func waitSQLiForm(ch <-chan sqliFormEvent, generation int) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return sqliFormClosed{generation}
		}
		return sqliFormDelivery{ev, ch}
	}
}
func (m model) openSQLiForm() (tea.Model, tea.Cmd) {
	if m.sqliForm.projectID == m.current.ID && m.sqliForm.busy {
		m.screen = "sqli-form"
		return m, nil
	}
	if m.sqliForm.cancel != nil {
		m.sqliForm.cancel()
	}
	host := m.smbBrowser.host
	targetURL := ""
	for i, s := range m.servicesFor(m.currentHost()) {
		if web, ok := discovery.WebURL(s); ok {
			targetURL = web
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	if targetURL == "" && host != "" {
		targetURL = "http://" + net.JoinHostPort(host, "80") + "/"
	}
	timeout := m.current.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	m.sqliForm = sqliFormState{projectID: m.current.ID, generation: m.sqliForm.generation + 1, options: engine.SQLiFormOptions{URL: targetURL, Timeout: time.Duration(timeout) * time.Second, Concurrency: 4}}
	m.screen = "sqli-form"
	m.message = ""
	return m, nil
}
func (m model) updateSQLiForm(key string) (tea.Model, tea.Cmd) {
	b := &m.sqliForm
	if b.detail {
		if key == "esc" || key == "enter" || key == "q" {
			b.detail = false
		}
		return m, nil
	}
	if b.busy {
		switch key {
		case "esc":
			b.cancel()
			m.message = "Останавливаю проверку SQLi…"
			return m, nil
		case "up", "k", "down", "j", "pgup", "pgdown", "enter", "e":
		default:
			return m, nil
		}
	}
	switch key {
	case "esc", "q":
		m.screen = "interaction-menu"
	case "u":
		m.startInput("sqli-form-url")
		m.input = b.options.URL
	case "v":
		m.startInput("sqli-form-vhost")
		m.input = b.options.VirtualHost
	case "o":
		m.startInput("sqli-form-cookie")
		m.input = b.options.Cookie
	case "c":
		m.startInput("sqli-form-workers")
		m.input = fmt.Sprint(max(1, b.options.Concurrency))
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "s":
		return m.startSQLiForm()
	case "enter":
		if len(b.hits) > 0 {
			b.detail = true
		} else {
			return m.startSQLiForm()
		}
	case "up", "k":
		b.index = max(0, b.index-1)
	case "down", "j":
		b.index = min(max(0, len(b.hits)-1), b.index+1)
	case "pgup":
		b.index = max(0, b.index-10)
	case "pgdown":
		b.index = min(max(0, len(b.hits)-1), b.index+10)
	case "e":
		m.message = m.exportSQLiForm()
	}
	return m, nil
}
func (m model) startSQLiForm() (tea.Model, tea.Cmd) {
	b := &m.sqliForm
	if b.busy {
		return m, nil
	}
	if !m.current.AllowExploit {
		m.message = "Проверка SQLi отправляет инъекционные payload'ы и требует AllowExploit"
		return m, nil
	}
	parsed, err := url.Parse(b.options.URL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		m.message = "Укажи HTTP/HTTPS URL клавишей u"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.busy = true
	b.generation++
	b.hits = nil
	b.index = 0
	b.done = 0
	b.total = 0
	b.errors = 0
	b.forms = 0
	b.limitation = ""
	m.message = ""
	b.projectID = m.current.ID
	generation, options, store, project := b.generation, b.options, m.store, m.current
	events := make(chan sqliFormEvent, 64)
	run := func() tea.Msg {
		defer cancel()
		defer close(events)
		var runID int64
		if store != nil && project.ID > 0 {
			var startErr error
			runID, startErr = store.StartRun(ctx, project.ID)
			if startErr != nil {
				return sqliFormDone{generation: generation, err: startErr}
			}
		}
		result, err := engine.ScanSQLiForms(ctx, options, func(p engine.SQLiFormProgress) {
			select {
			case events <- sqliFormEvent{generation, p}:
			case <-ctx.Done():
			}
		})
		if store != nil && project.ID > 0 {
			saveCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			var saveErr error
			if runID > 0 {
				for _, hit := range result.Hits {
					saveErr = store.SaveFinding(saveCtx, runID, domain.Finding{TemplateID: "native/sqli-form", Name: fmt.Sprintf("Web: SQL-инъекция в форме (%s, параметр %s)", hit.Technique, hit.Parameter), Severity: "high", Target: options.URL, MatchedAt: hit.Action, Evidence: fmt.Sprintf("method=%s; technique=%s; dbms=%s; payload=%s; %s; virtual host=%s", hit.Method, hit.Technique, hit.DBMS, hit.Payload, hit.Evidence, options.VirtualHost), Risk: "active", Time: time.Now().UTC()})
					if saveErr != nil {
						break
					}
				}
				status := "completed"
				if ctx.Err() != nil {
					status = "cancelled"
				} else if err != nil || saveErr != nil {
					status = "failed"
				}
				finishCtx, finishStop := context.WithTimeout(context.Background(), 3*time.Second)
				finishErr := store.FinishRun(finishCtx, runID, status)
				finishStop()
				if saveErr == nil {
					saveErr = finishErr
				}
			}
			if saveErr != nil && err == nil {
				err = saveErr
			}
		}
		return sqliFormDone{generation, result, err}
	}
	return m, tea.Batch(run, waitSQLiForm(events, generation))
}
func (m model) applySQLiFormEvent(ev sqliFormEvent, ch <-chan sqliFormEvent) (tea.Model, tea.Cmd) {
	b := &m.sqliForm
	if b.generation == ev.generation && b.busy {
		p := ev.progress
		b.done, b.total = p.Done, p.Total
		if p.Hit != nil {
			b.hits = append(b.hits, *p.Hit)
		}
	}
	return m, waitSQLiForm(ch, ev.generation)
}
func (m model) applySQLiFormDone(done sqliFormDone) (tea.Model, tea.Cmd) {
	b := &m.sqliForm
	if b.generation != done.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	b.hits = done.result.Hits
	b.done, b.total, b.errors, b.forms = done.result.Done, done.result.Total, done.result.Errors, done.result.Forms
	b.limitation = done.result.Limitation
	b.index = min(b.index, max(0, len(b.hits)-1))
	m.message = fmt.Sprintf("Форм найдено %d · параметров проверено %d/%d · уязвимо %d · ошибок %d", b.forms, b.done, b.total, len(b.hits), b.errors)
	if done.err != nil {
		m.message += " · " + done.err.Error()
	}
	if m.store != nil && m.current.ID > 0 {
		m.history, _ = m.store.Runs(m.ctx, m.current.ID)
	}
	return m, nil
}
func (m model) exportSQLiForm() string {
	if len(m.sqliForm.hits) == 0 {
		return "Нет находок для экспорта"
	}
	dir := filepath.Join(m.appDir, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err.Error()
	}
	f, err := os.CreateTemp(dir, "sqli-form-*.csv")
	if err != nil {
		return err.Error()
	}
	writer := csv.NewWriter(f)
	err = writer.Write([]string{"form_url", "action", "method", "parameter", "technique", "dbms", "payload", "evidence"})
	for _, h := range m.sqliForm.hits {
		if err != nil {
			break
		}
		err = writer.Write([]string{h.FormURL, h.Action, h.Method, h.Parameter, h.Technique, h.DBMS, h.Payload, h.Evidence})
	}
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err.Error()
	}
	return "CSV: " + f.Name()
}
func (m model) viewSQLiForm(w int) string {
	b := m.sqliForm
	o := b.options
	body := headingStyle.Render("Web — SQL-инъекции в формах") + "\n" + sanitizeWinRMText(o.URL) + "\n"
	if b.detail && b.index < len(b.hits) {
		h := b.hits[b.index]
		body += fmt.Sprintf("\nФорма: %s\nAction: %s\nМетод: %s\nПараметр: %s\nТехника: %s\nDBMS: %s\nPayload: %s\n\n%s\n\nEsc — результаты", sanitizeWinRMText(h.FormURL), sanitizeWinRMText(h.Action), h.Method, sanitizeWinRMText(h.Parameter), h.Technique, smbDisplayName(h.DBMS), sanitizeWinRMText(h.Payload), sanitizeWinRMText(h.Evidence))
		return m.renderPanel(w, body)
	}
	cookieStatus := "нет"
	if o.Cookie != "" {
		cookieStatus = fmt.Sprintf("задан (%d байт)", len(o.Cookie))
	}
	body += fmt.Sprintf("Virtual host: %s · Cookie: %s · потоки: %d · проверка TLS: %t\n", smbDisplayName(o.VirtualHost), cookieStatus, max(1, o.Concurrency), !o.Insecure)
	body += "u URL · v virtual host · o Cookie · c потоки · t TLS · s запуск · e CSV · Enter детали\nНативные проверки: error-based, boolean-based blind, time-based blind. Требует AllowExploit.\n"
	body += fmt.Sprintf("Форм найдено %d · проверено %d/%d · уязвимо %d · ошибок %d\n", b.forms, b.done, b.total, len(b.hits), b.errors)
	if b.limitation != "" {
		body += sanitizeWinRMText(b.limitation) + "\n"
	}
	body += "Техника          DBMS           Параметр / форма\n"
	lo, hi := windowRange(b.index, len(b.hits), max(1, m.panelRows()-10))
	for i := lo; i < hi; i++ {
		h := b.hits[i]
		line := fmt.Sprintf("%-16s %-14s %s=%s", h.Technique, smbDisplayName(h.DBMS), h.Parameter, h.Action)
		body += renderListRow(ansi.Truncate(sanitizeWinRMText(line), max(1, w-8), "…"), i == b.index, w)
	}
	if b.busy {
		body += "\nВыполняется… Esc — остановить, результаты сохранятся"
	}
	return m.renderPanel(w, body)
}
