package tui

import (
	"context"
	"encoding/csv"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type webDiscoveryState struct {
	wordlists                                        []webWordlistChoice
	wordlistIndex                                    int
	wordlistFilter                                   string
	projectID                                        int64
	options                                          engine.WebDiscoveryOptions
	generation, index, done, total, errors, filtered int
	busy                                             bool
	cancel                                           context.CancelFunc
	hits                                             []engine.WebDiscoveryHit
	detail                                           bool
}
type webDiscoveryEvent struct {
	generation int
	progress   engine.WebDiscoveryProgress
}
type webDiscoveryDelivery struct {
	event   webDiscoveryEvent
	channel <-chan webDiscoveryEvent
}
type webDiscoveryClosed struct{ generation int }
type webDiscoveryDone struct {
	generation int
	result     engine.WebDiscoveryResult
	err        error
}

func waitWebDiscovery(ch <-chan webDiscoveryEvent, generation int) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return webDiscoveryClosed{generation}
		}
		return webDiscoveryDelivery{ev, ch}
	}
}
func (m model) openWebDiscovery() (tea.Model, tea.Cmd) {
	if m.webDiscovery.projectID == m.current.ID && m.webDiscovery.busy {
		m.screen = "web-discovery"
		return m, nil
	}
	if m.webDiscovery.cancel != nil {
		m.webDiscovery.cancel()
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
	m.webDiscovery = webDiscoveryState{projectID: m.current.ID, generation: m.webDiscovery.generation + 1, options: engine.WebDiscoveryOptions{URL: targetURL, Wordlist: defaultWebWordlist(m.appDir), RPS: m.current.RPS, Concurrency: min(64, max(1, m.current.Concurrency)), Timeout: time.Duration(timeout) * time.Second, FilterWildcard: true}}
	m.screen = "web-discovery"
	m.message = ""
	return m, nil
}
func (m model) updateWebDiscovery(key string) (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
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
			m.message = "Останавливаю веб-перебор…"
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
		m.startInput("web-discovery-url")
		m.input = b.options.URL
	case "w":
		return m.openWebWordlists()
	case "x":
		m.startInput("web-discovery-extensions")
		m.input = b.options.Extensions
	case "v":
		m.startInput("web-discovery-vhost")
		m.input = b.options.VirtualHost
	case "f":
		m.startInput("web-discovery-statuses")
		m.input = b.options.Statuses
	case "z":
		m.startInput("web-discovery-sizes")
		m.input = b.options.ExcludeSizes
	case "r":
		m.startInput("web-discovery-rps")
		m.input = fmt.Sprint(b.options.RPS)
	case "c":
		m.startInput("web-discovery-workers")
		m.input = fmt.Sprint(max(1, b.options.Concurrency))
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "a":
		b.options.FilterWildcard = !b.options.FilterWildcard
	case "s":
		return m.startWebDiscovery()
	case "enter":
		if len(b.hits) > 0 {
			b.detail = true
		} else {
			return m.startWebDiscovery()
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
		m.message = m.exportWebDiscovery()
	}
	return m, nil
}
func (m model) startWebDiscovery() (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
	if b.busy {
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
	b.filtered = 0
	m.message = ""
	b.projectID = m.current.ID
	generation, options, store, project := b.generation, b.options, m.store, m.current
	events := make(chan webDiscoveryEvent, 64)
	run := func() tea.Msg {
		defer cancel()
		defer close(events)
		var runID int64
		if store != nil && project.ID > 0 {
			var startErr error
			runID, startErr = store.StartRun(ctx, project.ID)
			if startErr != nil {
				return webDiscoveryDone{generation: generation, err: startErr}
			}
		}
		lastReport := time.Time{}
		result, err := engine.DiscoverWeb(ctx, options, func(p engine.WebDiscoveryProgress) {
			if p.Hit == nil && p.Done != 0 && p.Done != p.Total && p.Done%10 != 0 && time.Since(lastReport) < 250*time.Millisecond {
				return
			}
			select {
			case events <- webDiscoveryEvent{generation, p}:
				lastReport = time.Now()
			case <-ctx.Done():
			}
		})
		if store != nil && project.ID > 0 {
			saveCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			var saveErr error
			if runID > 0 {
				for _, hit := range result.Hits {
					saveErr = store.SaveFinding(saveCtx, runID, domain.Finding{TemplateID: "native/web-discovery", Name: fmt.Sprintf("Web: найден путь (HTTP %d)", hit.Status), Severity: "info", Target: options.URL, MatchedAt: hit.URL, Evidence: fmt.Sprintf("status=%d; bytes=%d; Location=%s; title=%s; server=%s; virtual host=%s", hit.Status, hit.Size, hit.Location, hit.Title, hit.Server, options.VirtualHost), Risk: "active", Time: time.Now().UTC()})
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
		return webDiscoveryDone{generation, result, err}
	}
	return m, tea.Batch(run, waitWebDiscovery(events, generation))
}
func (m model) applyWebDiscoveryEvent(ev webDiscoveryEvent, ch <-chan webDiscoveryEvent) (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
	if b.generation == ev.generation && b.busy {
		p := ev.progress
		b.done, b.total, b.errors, b.filtered = p.Done, p.Total, p.Errors, p.Filtered
		if p.Hit != nil {
			b.hits = append(b.hits, *p.Hit)
		}
	}
	return m, waitWebDiscovery(ch, ev.generation)
}
func (m model) applyWebDiscoveryDone(done webDiscoveryDone) (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
	if b.generation != done.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	b.hits = done.result.Hits
	b.done, b.total, b.errors, b.filtered = done.result.Done, done.result.Total, done.result.Errors, done.result.Filtered
	b.index = min(b.index, max(0, len(b.hits)-1))
	m.message = fmt.Sprintf("Проверено %d/%d · найдено %d · ошибок %d", b.done, b.total, len(b.hits), b.errors)
	if done.err != nil {
		m.message += " · " + done.err.Error()
	} else if done.result.ErrorSample != "" {
		m.message += " · " + done.result.ErrorSample
	}
	if m.store != nil && m.current.ID > 0 {
		m.history, _ = m.store.Runs(m.ctx, m.current.ID)
	}
	return m, nil
}
func (m model) exportWebDiscovery() string {
	if len(m.webDiscovery.hits) == 0 {
		return "Нет найденных путей для экспорта"
	}
	dir := filepath.Join(m.appDir, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err.Error()
	}
	f, err := os.CreateTemp(dir, "web-discovery-*.csv")
	if err != nil {
		return err.Error()
	}
	writer := csv.NewWriter(f)
	err = writer.Write([]string{"url", "status", "bytes", "location", "title", "server", "content-type"})
	for _, h := range m.webDiscovery.hits {
		if err != nil {
			break
		}
		err = writer.Write([]string{h.URL, strconv.Itoa(h.Status), strconv.FormatInt(h.Size, 10), h.Location, h.Title, h.Server, h.ContentType})
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
func (m model) viewWebDiscovery(w int) string {
	b := m.webDiscovery
	o := b.options
	wordlist := o.Wordlist
	if wordlist == "" {
		wordlist = "встроенный короткий"
	}
	body := headingStyle.Render("Web — каталоги и файлы") + "\n" + sanitizeWinRMText(o.URL) + "\n"
	if b.detail && b.index < len(b.hits) {
		h := b.hits[b.index]
		body += fmt.Sprintf("\nURL: %s\nHTTP: %d\nРазмер: %d байт\nLocation: %s\nTitle: %s\nServer: %s\nContent-Type: %s\n\nEsc — результаты", sanitizeWinRMText(h.URL), h.Status, h.Size, sanitizeWinRMText(h.Location), sanitizeWinRMText(h.Title), sanitizeWinRMText(h.Server), sanitizeWinRMText(h.ContentType))
		return m.renderPanel(w, body)
	}
	body += fmt.Sprintf("Словарь: %s · расширения: %s\nRPS: %d · потоки: %d · проверка TLS: %t · wildcard-фильтр: %t\n", smbDisplayName(wordlist), smbDisplayName(o.Extensions), o.RPS, o.Concurrency, !o.Insecure, o.FilterWildcard)
	body += "u URL · w словарь · x расширения · v virtual host · f статусы · z исключить размеры\nr RPS · c потоки · t TLS · a wildcard · s запуск · e CSV · Enter детали\n"
	body += fmt.Sprintf("Проверено %d/%d · найдено %d · отфильтровано %d · ошибок %d\n", b.done, b.total, len(b.hits), b.filtered, b.errors)
	body += "HTTP  Байт       Путь / перенаправление\n"
	lo, hi := windowRange(b.index, len(b.hits), max(1, m.panelRows()-10))
	for i := lo; i < hi; i++ {
		h := b.hits[i]
		path := h.URL
		if parsed, err := url.Parse(h.URL); err == nil {
			path = parsed.EscapedPath()
		}
		if h.Location != "" {
			path += " → " + h.Location
		}
		if h.Title != "" {
			path += "  [" + h.Title + "]"
		}
		line := fmt.Sprintf("%-5d %-10d %s", h.Status, h.Size, sanitizeWinRMText(path))
		body += renderListRow(ansi.Truncate(line, max(1, w-8), "…"), i == b.index, w)
	}
	if b.busy {
		body += "\nВыполняется… Esc — остановить, результаты сохранятся"
	}
	return m.renderPanel(w, body)
}
