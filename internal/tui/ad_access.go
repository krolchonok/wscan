package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

var adAccessModes = []struct{ id, name string }{
	{"coercion-discovery", "Coerce: проверить доступность RPC-интерфейсов машин TCP/445"},
	{"coercion", "Coerce: машины TCP/445 → локальный SMB-приёмник (5 RPC-методов)"},
	{"directory", "LDAP-аудит: учётки, политики, delegation, trusts, LAPS, gMSA, AD CS"},
	{"asrep", "AS-REP: LDAP-кандидаты DONT_REQ_PREAUTH (без запроса билета)"},
	{"sysvol", "SYSVOL / NETLOGON: обнаружение устаревших GPP cpassword (без чтения паролей)"},
	{"ldap-security", "LDAP signing / LDAPS channel binding: проба с выбранной учёткой"},
	{"bloodhound-ce", "BloodHound CE: удалённый сбор домена → ZIP (LDAP, без агента)"},
}

func (m *model) openADAccess() {
	m.adAccessReturn = m.screen
	m.adAccessHost, m.adAccessDomain = "", ""
	m.adAccessIndex, m.adAccessCred = 0, -1
	m.adBloodHoundPort, m.adBloodHoundLimit = 636, 5000
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err == nil {
		m.adAccessCreds = creds
	} else {
		m.adAccessCreds = nil
		m.message = "Не удалось загрузить учётки: " + err.Error()
	}
	m.screen = "ad-access"
}

func (m model) updateADAccess(key string) (tea.Model, tea.Cmd) {
	if key == "p" && !m.adAccessJobRunning() {
		return m.toggleResponder()
	}
	if m.adAccessJobRunning() {
		if key == "esc" || key == "q" {
			if j := m.jobByID(m.adAccessJobID); j != nil && j.cancel != nil {
				j.cancel()
			}
			m.message = "Останавливаю AD-проверку…"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = m.adAccessReturn
		m.message = ""
	case "up", "k":
		m.adAccessIndex = max(0, m.adAccessIndex-1)
	case "down", "j":
		m.adAccessIndex = min(len(adAccessModes)-1, m.adAccessIndex+1)
	case "v":
		return m.toggleResponderDebug()
	case "l":
		if adAccessModes[m.adAccessIndex].id == "bloodhound-ce" {
			if m.adBloodHoundPort == 389 {
				m.adBloodHoundPort = 636
			} else {
				m.adBloodHoundPort = 389
			}
		}
	case "n":
		if adAccessModes[m.adAccessIndex].id == "bloodhound-ce" {
			m.startInput("ad-bloodhound-limit")
		}
	case "h":
		m.startInput("ad-access-host")
	case "r":
		m.startInput("ad-coerce-callback")
	case "d":
		m.startInput("ad-access-domain")
	case "c":
		if len(m.adAccessCreds) == 0 {
			m.message = "В проекте нет сохранённых учёток; нажми c в окне Credentials, затем вернись сюда"
		} else {
			m.adAccessCred++
			if m.adAccessCred >= len(m.adAccessCreds) {
				m.adAccessCred = -1
				m.message = "Учётка не выбрана (anonymous)"
			} else {
				m.message = "Учётка: " + credIdentLabel(m.adAccessCreds[m.adAccessCred])
				if m.screen == "coerce-setup" {
					m.adAccessDomain = m.adAccessCreds[m.adAccessCred].Domain
				}
			}
		}
	case "enter":
		return m.startADAccess()
	}
	return m, nil
}

func (m model) adAccessJobRunning() bool {
	j := m.jobByID(m.adAccessJobID)
	return j != nil && j.status == statusRunning
}

func (m model) viewADAccess(w int) string {
	body := headingStyle.Render("AD — учётки и первоначальный доступ") + "\n\n"
	cred := "не выбрана (anonymous для SYSVOL)"
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = credIdentLabel(m.adAccessCreds[m.adAccessCred])
	}
	body += fmt.Sprintf("Хост: %s · h изменить (пустой — машины проекта для Coerce)\nДомен: %s · d изменить\nУчётка: %s · c выбрать сохранённую\n\n", valueOr(m.adAccessHost, "не задан"), valueOr(m.adAccessDomain, "не задан"), cred)
	if strings.HasPrefix(adAccessModes[m.adAccessIndex].id, "coercion") {
		scope := "выбранные машины с 445, иначе все с 445; h — один хост"
		if m.adAccessHost != "" {
			scope = "только " + m.adAccessHost + "; h — изменить"
		}
		body += fmt.Sprintf("Приёмник: %s:445 · r изменить\nЦели Coerce: %d · %s\n\n", valueOr(m.adCoerceCallback, "не задан"), len(m.coercionTargets()), scope)
	}
	body += fmt.Sprintf("Responder: %s · p запустить/остановить · адрес: %s:445 (r)\n\n", m.responderStatus(), valueOr(m.adCoerceCallback, "не задан"))
	if adAccessModes[m.adAccessIndex].id == "bloodhound-ce" {
		port, limit := m.bloodHoundSettings()
		body += fmt.Sprintf("BloodHound CE · LDAP/%d (l) · лимит объектов/членов группы: %d (n)\n", port, limit)
		body += "Область: выбранный домен; рабочие станции не опрашиваются.\nЭкспорт: " + filepath.Join(m.appDir, "exports", "bloodhound") + "\n"
		body += "Не собираются: ACL, AD CS, сессии и локальные права.\n\n"
	}
	body += fmt.Sprintf("Диагностика Responder: %t · v переключить · журнал: g → Responder → r\n\n", m.responderDebug)
	body += "↑/↓ выбрать проверку · Enter запустить · Esc назад\n\n"
	for i, row := range adAccessModes {
		body += renderListRow(row.name, i == m.adAccessIndex, w)
	}
	body += "\nCoerce вызывает обратную SMB-аутентификацию; приёмник хранит только события и заявленную идентичность. Результаты — в «5 Результаты»."
	if m.adAccessJobRunning() {
		body += "\n\nВыполняется проверка… Esc — отменить"
	}
	return m.renderPanel(w, body)
}
func valueOr(v, empty string) string {
	if strings.TrimSpace(v) == "" {
		return empty
	}
	return v
}

func (m model) startADAccess() (tea.Model, tea.Cmd) {
	if m.current.ID == 0 {
		m.message = "Сначала открой проект"
		return m, nil
	}
	if strings.HasPrefix(adAccessModes[m.adAccessIndex].id, "coercion") {
		return m.startCoercion()
	}
	if strings.TrimSpace(m.adAccessHost) == "" || strings.TrimSpace(m.adAccessDomain) == "" {
		m.message = "Укажи хост контроллера (h) и домен (d)"
		return m, nil
	}
	mode := adAccessModes[m.adAccessIndex].id
	var cred domain.Credential
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = m.adAccessCreds[m.adAccessCred]
	}
	o := adscan.AccessOptions{Host: strings.TrimSpace(m.adAccessHost), Domain: strings.TrimSpace(m.adAccessDomain), Mode: mode, Credential: cred, LDAPPort: 636, MaxObjects: 5000, ExportDir: filepath.Join(m.appDir, "exports", "ad")}
	if mode == "bloodhound-ce" {
		if cred.Username == "" {
			m.message = "Выбери доменную учётку (c): BloodHound не собирается анонимно"
			return m, nil
		}
		o.LDAPPort, o.MaxObjects = m.bloodHoundSettings()
		o.ExportDir = filepath.Join(m.appDir, "exports", "bloodhound")
	}
	worker := m
	m.adAccessJobID = m.jobSeq + 1
	m.message = ""
	m.launch("ad-access", "AD "+mode+" · "+o.Host, []string{o.Host}, worker.runADAccess(o))
	return m, nil
}

func (m model) runADAccess(o adscan.AccessOptions) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		emit("AD " + o.Mode + ": " + o.Host)
		runID, err := m.store.StartRun(ctx, m.current.ID)
		if err != nil {
			return engine.Result{}, err
		}
		status := "completed"
		defer func() { _ = m.store.FinishRun(context.Background(), runID, status) }()
		var report adscan.AccessReport
		if o.Mode == "bloodhound-ce" {
			report, err = adscan.RunBloodHound(ctx, adscan.BloodHoundOptions{AccessOptions: o, Progress: func(s string) { emit(s) }})
		} else {
			report, err = adscan.RunAccess(ctx, o)
		}
		if err != nil {
			status = "failed"
			return engine.Result{RunID: runID, TargetsScanned: 1, Errors: []string{err.Error()}}, err
		}
		if len(report.Artifacts) > 0 {
			report.Checks = append(report.Checks, adscan.AccessCheck{ID: "artifacts", Name: "Локальные артефакты", State: "observed", Severity: "info", Evidence: strings.Join(report.Artifacts, "\n")})
		}
		if err = writeADReport(o.ExportDir, &report); err != nil {
			status = "failed"
			return engine.Result{RunID: runID, TargetsScanned: 1, Errors: []string{err.Error()}}, err
		}
		findings := report.Findings()
		for _, f := range findings {
			if err = m.store.SaveFinding(ctx, runID, f); err != nil {
				status = "failed"
				return engine.Result{RunID: runID, TargetsScanned: 1, Findings: findings, Errors: []string{err.Error()}}, err
			}
		}
		return engine.Result{RunID: runID, TargetsScanned: 1, Findings: findings}, nil
	}
}

func writeADReport(dir string, r *adscan.AccessReport) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "ad-report-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(r)
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	r.Artifacts = append(r.Artifacts, name)
	return nil
}

func (m model) coercionTargets() []string {
	if h := strings.TrimSpace(m.adAccessHost); h != "" {
		return []string{h}
	}
	hosts := []string{}
	seen := map[string]bool{}
	selected := false
	for _, v := range m.selectedHosts {
		if v {
			selected = true
			break
		}
	}
	for bucket, info := range m.inventory {
		if selected && !m.selectedHosts[bucket] {
			continue
		}
		for _, service := range info.services {
			if service.Port != 445 || (service.Protocol != "" && service.Protocol != "tcp") || (service.State != "" && service.State != "open") {
				continue
			}
			host := service.Host
			if host == "" {
				host = bucket
			}
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}
func (m model) startCoercion() (tea.Model, tea.Cmd) {
	targets := m.coercionTargets()
	if len(targets) == 0 {
		m.message = "Нет машин с открытым TCP/445; выполни поиск портов или укажи один хост (h)"
		return m, nil
	}
	discoverOnly := adAccessModes[m.adAccessIndex].id == "coercion-discovery"
	if !discoverOnly && strings.TrimSpace(m.adCoerceCallback) == "" {
		m.message = "Укажи локальный адрес приёмника (r)"
		return m, nil
	}
	if !discoverOnly && !m.coercePortApproved && !m.responderRunningAtCallback() {
		return m.requestCoercionPort("coercion")
	}
	m.coercePortApproved = false
	var cred domain.Credential
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = m.adAccessCreds[m.adAccessCred]
	}
	o := adscan.CoercionOptions{ReceiverDebug: m.responderDebug, DiscoverOnly: discoverOnly, Targets: targets, Callback: strings.TrimSpace(m.adCoerceCallback), Credential: adscan.AccessOptions{Domain: strings.TrimSpace(m.adAccessDomain), Credential: cred}}
	worker := m
	m.adAccessJobID = m.jobSeq + 1
	m.message = ""
	title := fmt.Sprintf("Coerce · %d машин · %s:445", len(targets), o.Callback)
	if discoverOnly {
		title = fmt.Sprintf("Coerce RPC discovery · %d машин", len(targets))
	}
	lease := m.coercePortLease
	m.coercePortLease = nil
	m.launch("ad-access", title, targets, worker.runCoercion(o, lease))
	return m, nil
}
func (m model) runCoercion(o adscan.CoercionOptions, leases ...*adscan.PortLease) runFunc {
	return func(ctx context.Context, emit progressReporter) (output engine.Result, returnedError error) {
		if len(leases) > 0 && leases[0] != nil {
			defer func() {
				if err := leases[0].Restore(); err != nil {
					returnedError = errors.Join(returnedError, fmt.Errorf("восстановление Samba: %w", err))
					output.Errors = append(output.Errors, err.Error())
				}
			}()
		}
		runID, err := m.store.StartRun(ctx, m.current.ID)
		if err != nil {
			return engine.Result{}, err
		}
		status := "completed"
		defer func() { _ = m.store.FinishRun(context.Background(), runID, status) }()
		var reports []adscan.AccessReport
		var scanErr error
		if o.Methods != nil && len(o.Methods) == 1 && o.Methods[0] == "responder" {
			reports, scanErr = adscan.RunResponderWithOptions(ctx, o.Callback, o.Targets, adscan.ResponderOptions{Debug: o.ReceiverDebug}, func(s string) { emit(s) })
		} else {
			reports, scanErr = adscan.RunCoercion(ctx, o, func(s string) { emit(s) })
		}
		result := engine.Result{RunID: runID, TargetsScanned: len(reports)}
		// Persist partial results even when the operator cancels the job.
		saveCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, report := range reports {
			if e := writeADReport(filepath.Join(m.appDir, "exports", "ad"), &report); e != nil {
				result.Errors = append(result.Errors, e.Error())
				status = "failed"
			}
			for _, f := range report.Findings() {
				result.Findings = append(result.Findings, f)
				if e := m.store.SaveFinding(saveCtx, runID, f); e != nil {
					result.Errors = append(result.Errors, e.Error())
					status = "failed"
				}
			}
		}
		if scanErr != nil {
			status = "failed"
			result.Errors = append(result.Errors, scanErr.Error())
		}
		if scanErr == nil && len(result.Errors) > 0 {
			scanErr = fmt.Errorf("ошибки сохранения: %s", strings.Join(result.Errors, "; "))
		}
		return result, scanErr
	}
}

func (m model) responderStatus() string {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		return j.stage
	}
	return "остановлен"
}
func (m model) toggleResponder() (tea.Model, tea.Cmd) {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		if j.cancel != nil {
			j.cancel()
		}
		m.message = "Останавливаю Responder; сохраняю события…"
		return m, nil
	}
	if m.current.ID == 0 {
		m.message = "Сначала открой проект"
		return m, nil
	}
	if strings.TrimSpace(m.adCoerceCallback) == "" {
		m.message = "Задай локальный IPv4 приёмника (r)"
		return m, nil
	}
	targets := m.coercionTargets()
	if len(targets) == 0 {
		m.message = "Выбери машины с 445 или укажи один хост (h)"
		return m, nil
	}
	o := adscan.CoercionOptions{ReceiverDebug: m.responderDebug, Targets: targets, Callback: strings.TrimSpace(m.adCoerceCallback), Methods: []string{"responder"}}
	worker := m
	if !m.coercePortApproved {
		return m.requestCoercionPort("responder")
	}
	m.coercePortApproved = false
	m.adResponderJobID = m.jobSeq + 1
	lease := m.coercePortLease
	m.coercePortLease = nil
	m.launch("responder", "Responder · "+o.Callback+":445", targets, worker.runCoercion(o, lease))
	return m, nil
}

func (m model) responderRunningAtCallback() bool {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		return strings.Contains(j.label, m.adCoerceCallback+":445")
	}
	return false
}

func (m model) bloodHoundSettings() (int, int) {
	port, limit := m.adBloodHoundPort, m.adBloodHoundLimit
	if port != 389 && port != 636 {
		port = 636
	}
	if limit < 1 || limit > 50000 {
		limit = 5000
	}
	return port, limit
}

func (m model) toggleResponderDebug() (tea.Model, tea.Cmd) {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		m.message = "Для смены диагностики останови Responder и запусти снова"
		return m, nil
	}
	m.responderDebug = !m.responderDebug
	m.message = fmt.Sprintf("Диагностика Responder: %t · подробные события в журнале задачи", m.responderDebug)
	return m, nil
}
