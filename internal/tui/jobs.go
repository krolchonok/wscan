package tui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

// Job kinds shown in the jobs panel and status bar.
const (
	jobDiscover = "discover"
	jobAlive    = "alive-hosts"
	jobPTR      = "ptr"
	jobChecks   = "checks"
	jobFull     = "full"
	jobPort     = "port"
	jobBulkPort = "bulk-port"
	jobAD       = "ad-scan"
)

// Job statuses.
const (
	statusRunning   = "running"
	statusDone      = "done"
	statusFailed    = "failed"
	statusCancelled = "cancelled"
)

// job is a single background unit of work. It lives in the model and is only
// mutated inside Update (single threaded); the worker goroutine talks back
// through the shared jobEvents channel, never by touching the struct directly.
type job struct {
	id        int
	projectID int64
	kind      string
	label     string
	targets   []string
	status    string
	stage     string
	completed int
	total     int
	runID     int64
	result    *engine.Result
	adResult  *adscan.Result
	findings  int
	errText   string
	started   time.Time
	ended     time.Time
	seen      bool // results already opened by the user
	cancel    context.CancelFunc
	scope     string
	service   *domain.Service
	checks    []string
	options   []string
	journal   []string
	logPath   string
	logError  string
	lastLog   time.Time
}

func (j *job) addLog(message string) {
	now := time.Now()
	line := now.Format("15:04:05") + "  " + message
	j.journal = append(j.journal, line)
	if len(j.journal) > 500 {
		j.journal = j.journal[len(j.journal)-500:]
	}
	j.lastLog = now
	if j.logPath == "" {
		return
	}
	f, err := os.OpenFile(j.logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err == nil {
		_, err = fmt.Fprintln(f, line)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		j.logError = err.Error()
	}
}

func (m model) initJobLog(j *job) {
	if m.appDir != "" {
		dir := filepath.Join(m.appDir, "logs")
		if err := os.MkdirAll(dir, 0700); err != nil {
			j.logError = err.Error()
		} else {
			j.logPath = filepath.Join(dir, fmt.Sprintf("scan-%s-%d.log", j.started.Format("20060102-150405.000000000"), j.id))
		}
	}
	j.addLog("Запуск: " + j.label)
	j.addLog(fmt.Sprintf("Проект: %s (#%d)", m.findProject(j.projectID).Name, j.projectID))
	j.addLog("Область: " + j.scope)
	for _, option := range j.options {
		j.addLog(option)
	}
	j.addLog(fmt.Sprintf("Выбрано проверок: %d", len(j.checks)))
	for _, id := range j.checks {
		j.addLog("Проверка: " + id)
	}
}

func (j *job) active() bool { return j.status == statusRunning }

func (j *job) progressText(width int) string {
	if j.total <= 0 && j.status != statusDone {
		return "… " + j.statusLabel()
	}
	percent := 100
	if j.total > 0 {
		percent = min(100, max(0, j.completed*100/j.total))
	}
	filled := width * percent / 100
	text := "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + fmt.Sprintf("] %3d%%", percent)
	if j.total > 0 {
		text += fmt.Sprintf(" %d/%d", j.completed, j.total)
	}
	return text
}

func (j *job) statusLabel() string {
	switch j.status {
	case statusRunning:
		return "выполняется"
	case statusFailed:
		return "ошибка"
	case statusCancelled:
		return "отменено"
	default:
		return "завершено"
	}
}

func (j *job) duration() time.Duration {
	if j.ended.IsZero() {
		return time.Since(j.started)
	}
	return j.ended.Sub(j.started)
}

// jobEvent is the only channel of communication from a worker goroutine back
// into the Bubble Tea update loop.
type jobEvent struct {
	id          int
	stage       string // non-empty: a progress update
	completed   int
	total       int
	hasProgress bool
	done        bool // true: terminal event carrying result/err
	result      engine.Result
	adResult    *adscan.Result
	projectID   int64
	projectName string
	err         error
}

// Counts describe progress within the current phase, not an estimated total.
type progressReporter func(stage string, counts ...int)

// runFunc is the actual work of a job.
type runFunc func(ctx context.Context, emit progressReporter) (engine.Result, error)

// waitForJob blocks on the shared channel and turns the next event into a
// tea.Msg. Update re-issues it after every event to keep listening.
func waitForJob(ch chan jobEvent) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// launch registers a background job and starts its goroutine. It mutates the
// model (jobs slice, counter) and is always called from Update on the value
// receiver, so the returned model must be propagated by the caller.
func (m *model) launch(kind, label string, targets []string, fn runFunc) {
	m.jobSeq++
	id := m.jobSeq
	ctx, cancel := context.WithCancel(m.ctx)
	j := &job{
		id:        id,
		projectID: m.current.ID,
		kind:      kind,
		label:     label,
		targets:   append([]string(nil), targets...),
		status:    statusRunning,
		stage:     "запуск…",
		started:   time.Now(),
		cancel:    cancel,
	}
	m.jobs = append(m.jobs, j)
	ch := m.jobEvents
	go func() {
		res, err := fn(ctx, func(stage string, counts ...int) {
			ev := jobEvent{id: id, stage: stage, hasProgress: true}
			if len(counts) == 2 {
				ev.completed, ev.total = counts[0], counts[1]
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
			}
		})
		ch <- jobEvent{id: id, done: true, result: res, err: err}
	}()
}

// applyJobEvent folds a worker event into the matching job.
func (m *model) applyJobEvent(ev jobEvent) {
	j := m.jobByID(ev.id)
	if j == nil {
		return
	}
	if !ev.done {
		if ev.stage != "" {
			shouldLog := ev.stage != j.stage || time.Since(j.lastLog) >= time.Second
			j.stage = ev.stage
			if ev.hasProgress {
				j.total = max(0, ev.total)
				j.completed = min(max(0, ev.completed), j.total)
				if j.kind == jobAD && j.id == m.adScanJobID {
					m.adScanDone, m.adScanTotal = j.completed, j.total
				}
			}
			if shouldLog {
				j.addLog(j.stage + " " + j.progressText(10))
			}
		}
		return
	}
	j.ended = time.Now()
	if j.kind == jobAD && j.id == m.adScanJobID {
		m.adScanRunning = false
		m.adScanResult = ev.adResult
		m.serviceIndex = 0
		if ev.err != nil {
			if ctxCancelled(ev.err) {
				m.message = "AD-сканирование остановлено."
			} else {
				m.adScanError = ev.err.Error()
			}
		} else if ev.adResult != nil {
			m.adScanDone = m.adScanTotal
			m.message = fmt.Sprintf("Сканирование завершено: адресов %d, AD-узлов %d.", ev.adResult.HostsScanned, len(ev.adResult.Hosts))
		}
	}
	if j.kind == jobAD && ev.projectID != 0 {
		existingProject := j.projectID != 0 && j.projectID == ev.projectID
		j.projectID = ev.projectID
		j.label = ev.projectName
		if err := m.reload(); err != nil {
			j.addLog("Результаты AD записаны, но список проектов не обновлён: " + err.Error())
		}
		project := m.findProject(ev.projectID)
		if project.ID == 0 {
			project = domain.Project{ID: ev.projectID, Name: ev.projectName}
		}
		m.openProject(project)
		if existingProject {
			j.addLog(fmt.Sprintf("Дополнен проект %q (ID %d)", ev.projectName, ev.projectID))
		} else {
			j.addLog(fmt.Sprintf("Создан проект %q (ID %d)", ev.projectName, ev.projectID))
		}
	}
	res := ev.result
	j.result = &res
	j.adResult = ev.adResult
	j.runID = res.RunID
	j.findings = len(groupedProjectResults(orderedResults(res.Findings)))
	for _, message := range res.Skipped {
		j.addLog("Пропущено: " + message)
	}
	for _, message := range res.Errors {
		j.addLog("Ошибка проверки: " + message)
	}
	if ev.err != nil {
		j.errText = ev.err.Error()
		if ctxCancelled(ev.err) {
			j.status = statusCancelled
			j.stage = "отменено"
		} else {
			j.status = statusFailed
			j.stage = "ошибка"
		}
		j.addLog(j.stage + ": " + j.errText)
		if j.kind == jobAD && j.id == m.adScanJobID {
			if ev.projectID != 0 {
				m.message = "Запись AD-результатов в проект завершилась ошибкой: " + ev.err.Error()
			} else {
				m.message = "AD-сканирование не завершено: " + ev.err.Error()
			}
		}
		return
	}
	j.status = statusDone
	j.completed = j.total
	j.stage = "готово"
	if len(res.Errors) > 0 {
		j.stage = "готово с ошибками"
	}
	if j.kind == jobPTR {
		j.addLog(fmt.Sprintf("PTR: найдено имён для %d адресов", len(res.LiveHosts)))
	} else if j.kind == jobAlive {
		j.addLog(fmt.Sprintf("Завершено: обнаружено живых хостов %d", len(res.LiveHosts)))
	} else {
		j.addLog(fmt.Sprintf("Завершено: запуск #%d, сервисов %d, результатов %d, ошибок проверок %d", j.runID, len(res.Services), j.findings, len(res.Errors)))
	}
	j.addLog(resultCounts(groupedProjectResults(orderedResults(res.Findings)), len(res.Errors)))
	if res.HTTPRequestsSaved > 0 {
		j.addLog(fmt.Sprintf("HTTP: сэкономлено повторных запросов — %d", res.HTTPRequestsSaved))
	}
	if j.projectID != 0 && j.projectID == m.current.ID {
		selectedNetworks := map[string]bool{}
		for _, target := range j.targets {
			if discovery.IsNetworkTarget(target) {
				selectedNetworks[target] = true
				delete(m.selectedNetworks, target)
			}
		}
		for _, host := range res.LiveHosts {
			if m.store != nil {
				if err := m.store.AddTarget(m.ctx, m.current.ID, host); err != nil {
					j.addLog("Не удалось сохранить хост " + host + ": " + err.Error())
				}
			}
			m.ensureHost(host)
			for cidr := range selectedNetworks {
				if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(net.ParseIP(host)) {
					if m.selectedHosts == nil {
						m.selectedHosts = map[string]bool{}
					}
					m.selectedHosts[host] = true
				}
			}
		}
		if len(res.LiveHosts) > 0 && m.store != nil {
			_ = m.reload()
			m.current = m.findProject(m.current.ID)
		}
		if j.kind == jobPTR {
			if m.hostNames == nil {
				m.hostNames = map[string][]string{}
			}
			if m.dnsChecked == nil {
				m.dnsChecked = map[string]time.Time{}
			}
			if m.dnsPinned == nil {
				m.dnsPinned = map[string]bool{}
			}
			for host, names := range res.HostNames {
				m.dnsPinned[host] = true
				m.hostNames[host] = names
				m.dnsChecked[host] = time.Now()
			}
		}
		if j.kind != jobAD {
			m.mergeResult(res, j.targets)
		}
		if j.kind == jobAD {
			if len(m.hostOrder) > 0 {
				m.screen = "desk"
			}
			m.message = fmt.Sprintf("Создан AD-проект %q: %d узлов, %d служб, %d результатов.", j.label, len(j.adResult.Hosts), len(res.Services), len(res.Findings))
		}
		if j.kind == jobAlive {
			m.hostIndex, m.focusCol, m.serviceIndex = -1, 0, -1
			m.message = fmt.Sprintf("Найдено %d хостов · Space выбрать · Enter найти порты", len(res.LiveHosts))
		}
		if j.kind == jobPTR {
			m.message = fmt.Sprintf("PTR: имена найдены для %d адресов · ошибок DNS: %d", len(res.LiveHosts), len(res.Errors))
		} else if len(res.LiveHosts) > 0 {
			j.addLog(fmt.Sprintf("Отвечающих хостов: %d", len(res.LiveHosts)))
		}
	}
}

type jobTick time.Time

func tickJobs() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return jobTick(t) })
}

func (m *model) jobByID(id int) *job {
	for _, j := range m.jobs {
		if j.id == id {
			return j
		}
	}
	return nil
}

// clearFinishedJobs drops every non-running job from
// the in-memory list (their results are already persisted in the store).
func (m *model) clearFinishedJobs() {
	kept := m.jobs[:0]
	for _, j := range m.jobs {
		if j.status != statusRunning {
			continue
		}
		kept = append(kept, j)
	}
	m.jobs = kept
}

func (m model) countJobs() (running, done, failed int) {
	for _, j := range m.jobs {
		switch j.status {
		case statusRunning:
			running++
		case statusDone:
			done++
			if j.result != nil && len(j.result.Errors) > 0 {
				failed++
			}
		case statusFailed, statusCancelled:
			failed++
		}
	}
	return
}

// unseenDone reports finished jobs whose results the user has not opened yet.
func (m model) unseenDone() int {
	n := 0
	for _, j := range m.jobs {
		if j.status == statusDone && !j.seen {
			n++
		}
	}
	return n
}

func ctxCancelled(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded ||
		(err != nil && (err.Error() == context.Canceled.Error() || err.Error() == "context canceled"))
}
