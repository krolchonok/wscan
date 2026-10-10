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

type fileUploadState struct {
	projectID                      int64
	options                        engine.FileUploadOptions
	generation, index, done, total int
	errors, forms                  int
	busy                           bool
	cancel                         context.CancelFunc
	hits                           []engine.FileUploadHit
	limitation                     string
	detail                         bool
}
type fileUploadEvent struct {
	generation int
	progress   engine.FileUploadProgress
}
type fileUploadDelivery struct {
	event   fileUploadEvent
	channel <-chan fileUploadEvent
}
type fileUploadClosed struct{ generation int }
type fileUploadDone struct {
	generation int
	result     engine.FileUploadResult
	err        error
}

func waitFileUpload(ch <-chan fileUploadEvent, generation int) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return fileUploadClosed{generation}
		}
		return fileUploadDelivery{ev, ch}
	}
}
func (m model) openFileUpload() (tea.Model, tea.Cmd) {
	if m.fileUpload.projectID == m.current.ID && m.fileUpload.busy {
		m.screen = "file-upload"
		return m, nil
	}
	if m.fileUpload.cancel != nil {
		m.fileUpload.cancel()
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
		timeout = 15
	}
	m.fileUpload = fileUploadState{projectID: m.current.ID, generation: m.fileUpload.generation + 1, options: engine.FileUploadOptions{URL: targetURL, Timeout: time.Duration(timeout) * time.Second, Concurrency: 4}}
	m.screen = "file-upload"
	m.message = ""
	return m, nil
}
func (m model) updateFileUpload(key string) (tea.Model, tea.Cmd) {
	b := &m.fileUpload
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
			m.message = "Останавливаю проверку загрузки файлов…"
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
		m.startInput("file-upload-url")
		m.input = b.options.URL
	case "v":
		m.startInput("file-upload-vhost")
		m.input = b.options.VirtualHost
	case "o":
		m.startInput("file-upload-cookie")
		m.input = b.options.Cookie
	case "c":
		m.startInput("file-upload-workers")
		m.input = fmt.Sprint(max(1, b.options.Concurrency))
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "s":
		return m.startFileUpload()
	case "enter":
		if len(b.hits) > 0 {
			b.detail = true
		} else {
			return m.startFileUpload()
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
		m.message = m.exportFileUpload()
	}
	return m, nil
}
func (m model) startFileUpload() (tea.Model, tea.Cmd) {
	b := &m.fileUpload
	if b.busy {
		return m, nil
	}
	if !m.current.AllowExploit {
		m.message = "Проверка загрузки заливает PHP-пробник на сервер и требует AllowExploit"
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
	events := make(chan fileUploadEvent, 64)
	run := func() tea.Msg {
		defer cancel()
		defer close(events)
		var runID int64
		if store != nil && project.ID > 0 {
			var startErr error
			runID, startErr = store.StartRun(ctx, project.ID)
			if startErr != nil {
				return fileUploadDone{generation: generation, err: startErr}
			}
		}
		result, err := engine.ScanFileUpload(ctx, options, func(p engine.FileUploadProgress) {
			select {
			case events <- fileUploadEvent{generation, p}:
			case <-ctx.Done():
			}
		})
		if store != nil && project.ID > 0 {
			saveCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			var saveErr error
			if runID > 0 {
				for _, hit := range result.Hits {
					saveErr = store.SaveFinding(saveCtx, runID, domain.Finding{TemplateID: "native/file-upload-rce", Name: fmt.Sprintf("Web: подтверждён RCE через загрузку файла (%s, поле %s)", hit.Technique, hit.Field), Severity: "critical", Target: options.URL, MatchedAt: hit.ServedAt, Evidence: fmt.Sprintf("action=%s; field=%s; technique=%s; filename=%s; %s; virtual host=%s", hit.Action, hit.Field, hit.Technique, hit.Filename, hit.Evidence, options.VirtualHost), Risk: "active", Time: time.Now().UTC()})
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
		return fileUploadDone{generation, result, err}
	}
	return m, tea.Batch(run, waitFileUpload(events, generation))
}
func (m model) applyFileUploadEvent(ev fileUploadEvent, ch <-chan fileUploadEvent) (tea.Model, tea.Cmd) {
	b := &m.fileUpload
	if b.generation == ev.generation && b.busy {
		p := ev.progress
		b.done, b.total = p.Done, p.Total
		if p.Hit != nil {
			b.hits = append(b.hits, *p.Hit)
		}
	}
	return m, waitFileUpload(ch, ev.generation)
}
func (m model) applyFileUploadDone(done fileUploadDone) (tea.Model, tea.Cmd) {
	b := &m.fileUpload
	if b.generation != done.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	b.hits = done.result.Hits
	b.done, b.total, b.errors, b.forms = done.result.Done, done.result.Total, done.result.Errors, done.result.Forms
	b.limitation = done.result.Limitation
	b.index = min(b.index, max(0, len(b.hits)-1))
	m.message = fmt.Sprintf("Форм найдено %d · полей проверено %d/%d · RCE подтверждён %d · ошибок %d", b.forms, b.done, b.total, len(b.hits), b.errors)
	if done.err != nil {
		m.message += " · " + done.err.Error()
	}
	if m.store != nil && m.current.ID > 0 {
		m.history, _ = m.store.Runs(m.ctx, m.current.ID)
	}
	return m, nil
}
func (m model) exportFileUpload() string {
	if len(m.fileUpload.hits) == 0 {
		return "Нет находок для экспорта"
	}
	dir := filepath.Join(m.appDir, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err.Error()
	}
	f, err := os.CreateTemp(dir, "file-upload-*.csv")
	if err != nil {
		return err.Error()
	}
	writer := csv.NewWriter(f)
	err = writer.Write([]string{"form_url", "action", "field", "technique", "filename", "served_at", "evidence"})
	for _, h := range m.fileUpload.hits {
		if err != nil {
			break
		}
		err = writer.Write([]string{h.FormURL, h.Action, h.Field, h.Technique, h.Filename, h.ServedAt, h.Evidence})
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
func (m model) viewFileUpload(w int) string {
	b := m.fileUpload
	o := b.options
	body := headingStyle.Render("Web — загрузка PHP-файлов (RCE)") + "\n" + sanitizeWinRMText(o.URL) + "\n"
	if b.detail && b.index < len(b.hits) {
		h := b.hits[b.index]
		body += fmt.Sprintf("\nФорма: %s\nAction: %s\nПоле: %s\nТехника: %s\nИмя файла: %s\nОтдаётся по адресу: %s\n\n%s\n\nEsc — результаты", sanitizeWinRMText(h.FormURL), sanitizeWinRMText(h.Action), h.Field, h.Technique, sanitizeWinRMText(h.Filename), sanitizeWinRMText(h.ServedAt), sanitizeWinRMText(h.Evidence))
		return m.renderPanel(w, body)
	}
	cookieStatus := "нет"
	if o.Cookie != "" {
		cookieStatus = fmt.Sprintf("задан (%d байт)", len(o.Cookie))
	}
	body += fmt.Sprintf("Virtual host: %s · Cookie: %s · потоки: %d · проверка TLS: %t\n", smbDisplayName(o.VirtualHost), cookieStatus, max(1, o.Concurrency), !o.Insecure)
	body += "u URL · v virtual host · o Cookie · c потоки · t TLS · s запуск · e CSV · Enter детали\nЗаливает безопасный маркерный PHP-пробник (echo, без side-effects) несколькими обходами фильтра расширений + .htaccess-трюк. Требует AllowExploit.\n"
	body += fmt.Sprintf("Форм найдено %d · проверено %d/%d · RCE подтверждён %d · ошибок %d\n", b.forms, b.done, b.total, len(b.hits), b.errors)
	if b.limitation != "" {
		body += sanitizeWinRMText(b.limitation) + "\n"
	}
	body += "Техника                      Поле       Куда отдаётся\n"
	lo, hi := windowRange(b.index, len(b.hits), max(1, m.panelRows()-10))
	for i := lo; i < hi; i++ {
		h := b.hits[i]
		line := fmt.Sprintf("%-28s %-10s %s", h.Technique, h.Field, h.ServedAt)
		body += renderListRow(ansi.Truncate(sanitizeWinRMText(line), max(1, w-8), "…"), i == b.index, w)
	}
	if b.busy {
		body += "\nВыполняется… Esc — остановить, результаты сохранятся"
	}
	return m.renderPanel(w, body)
}
