package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/engine"
)

// Rebuild identities from persisted findings, including the full user list.
// Do not reuse adScanResult, which may belong to a different open project.
func (m model) projectADInventory() adscan.Result {
	var r adscan.Result
	for address, info := range m.inventory {
		if info == nil {
			continue
		}
		host := adscan.Host{Address: address}
		var latest time.Time
		for _, f := range info.findings {
			if f.TemplateID != "adscan-rootdse" && f.TemplateID != "adscan-identity" {
				continue
			}
			if f.Time.Before(latest) {
				continue
			}
			var observed adscan.Host
			if f.Response != "" && json.Unmarshal([]byte(f.Response), &observed) == nil && observed.Domain != "" {
				host, latest = observed, f.Time
			} else if _, rest, ok := strings.Cut(f.Evidence, "; домен: "); ok {
				host.Domain = strings.TrimSpace(strings.Split(rest, ";")[0])
				latest = f.Time
			}
		}
		host.Address, host.Ports = address, nil
		for _, service := range info.services {
			if service.Protocol == "tcp" && service.State != "closed" {
				host.Ports = append(host.Ports, service.Port)
			}
		}
		r.Hosts = append(r.Hosts, host)
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].Address < r.Hosts[j].Address })
	return r
}

func (m *model) openASREPSetup() {
	m.screen, m.adASREPIndex, m.adASREPUsers = "asrep-setup", 3, ""
	// KDC is automatic by default, rather than the selected workstation.
	if m.adAccessHost != m.adAccessAutoHost && m.adAccessHost != m.adAccessManualHost {
		m.adAccessHost = ""
	}
	if m.adAccessDomain == "" {
		var domains []string
		for _, host := range m.projectADInventory().Hosts {
			if host.Domain != "" {
				domains = append(domains, host.Domain)
			}
		}
		domains = uniqueStrings(domains)
		if len(domains) == 1 {
			m.adAccessDomain = domains[0]
		}
		if len(domains) == 0 && len(m.adScanDNS.Domains) == 1 {
			m.adAccessDomain = m.adScanDNS.Domains[0]
		}
	}
}

func (m model) updateASREPSetup(key string) (tea.Model, tea.Cmd) {
	if m.adAccessJobRunning() {
		if key == "x" {
			if j := m.jobByID(m.adAccessJobID); j != nil && j.cancel != nil {
				j.cancel()
			}
		}
		return m, nil
	}
	switch key {
	case "up":
		m.adASREPIndex = max(0, m.adASREPIndex-1)
	case "down":
		m.adASREPIndex = min(4, m.adASREPIndex+1)
	case "left", "esc":
		m.screen = "ad-access"
	case "enter":
		switch m.adASREPIndex {
		case 0:
			m.startInput("ad-access-domain")
			m.input = m.adAccessDomain
		case 1:
			m.openADControllerPicker()
		case 2:
			m.startInput("asrep-users")
			m.input = m.adASREPUsers
		case 3:
			return m.startASREP()
		case 4:
			m.screen = "ad-access"
		}
	}
	return m, nil
}

func parseASREPUsersInput(input, realm string) ([]string, error) {
	users, err := adscan.ReadKerberosList(input, 5000)
	if err != nil {
		return nil, err
	}
	return adscan.NormalizeASREPUsers(users, realm, 5000)
}

func (m model) asrepOptions() (adscan.AccessOptions, error) {
	o := adscan.AccessOptions{Mode: "asrep", Domain: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m.adAccessDomain)), "."), Host: strings.TrimSpace(m.adAccessHost), DNS: m.adScanDNS, ExportDir: filepath.Join(m.appDir, "exports", "ad", fmt.Sprintf("project-%d", m.current.ID)), MaxObjects: 5000, RPS: m.current.RPS, Timeout: time.Duration(m.current.TimeoutSeconds) * time.Second}
	if o.Domain == "" {
		return o, fmt.Errorf("домен не определён; укажи его в первой строке")
	}
	details := m.projectADInventory()
	if m.adAccessNodesProject == m.current.ID {
		details.Hosts = append(details.Hosts, m.adAccessNodes...)
	}
	for _, host := range details.Hosts {
		if !strings.EqualFold(host.Domain, o.Domain) {
			continue
		}
		if m.adASREPUsers == "" {
			o.Users = append(o.Users, host.LDAPUsers...)
			o.Users = append(o.Users, host.ASREPUsers...)
		}
		if o.Host == "" {
			for _, port := range host.Ports {
				if port == 88 {
					o.Host = host.Address
					break
				}
			}
		}
	}
	var err error
	if m.adASREPUsers != "" {
		o.Users, err = parseASREPUsersInput(m.adASREPUsers, o.Domain)
	} else {
		o.Users, err = adscan.NormalizeASREPUsers(o.Users, o.Domain, 5000)
	}
	if m.adASREPUsers != "" && err == nil && len(o.Users) == 0 {
		err = fmt.Errorf("указанный список пользователей пуст")
	}
	return o, err
}

func (m model) viewASREPSetup(w int) string {
	users := "автоматически из проекта / anonymous LDAP"
	if m.adASREPUsers != "" {
		users = m.adASREPUsers
	}
	rows := []string{"Домен: " + valueOr(m.adAccessDomain, "не определён"), "KDC: " + valueOr(m.adAccessHost, "автоматически из проекта / DNS"), "Пользователи (имена или @файл): " + users, "Начать проверку", "Назад"}
	body := headingStyle.Render("AS-REP без пароля") + "\n\n"
	for i, row := range rows {
		body += renderListRow(row, i == m.adASREPIndex, w-4)
	}
	if m.adAccessJobRunning() {
		body += "\nВыполняется… x остановить"
	}
	return m.renderPanel(w, body)
}

func (m model) startASREP() (tea.Model, tea.Cmd) {
	if m.adAccessAutoBusy {
		m.message = "Определяю домен…"
		return m, nil
	}
	if m.current.ID == 0 {
		m.message = "Сначала открой проект"
		return m, nil
	}
	o, err := m.asrepOptions()
	if err != nil {
		m.message = err.Error()
		return m, nil
	}
	target := o.Host
	if target == "" {
		target = o.Domain
	}
	worker := m
	m.adAccessJobID, m.message = m.jobSeq+1, ""
	m.launch("ad-access", "AS-REP · "+o.Domain, []string{target}, worker.runASREP(o))
	return m, nil
}

func (m model) runASREP(o adscan.AccessOptions) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		runID, err := m.store.StartRun(ctx, m.current.ID)
		if err != nil {
			return engine.Result{}, err
		}
		status := "completed"
		defer func() { _ = m.store.FinishRun(context.Background(), runID, status) }()
		o.Progress = func(s string) { emit(s) }
		report, runErr := adscan.RunAccess(ctx, o)
		result := engine.Result{RunID: runID, TargetsScanned: 1}
		if runErr != nil {
			status = "failed"
			if ctx.Err() != nil {
				status = "cancelled"
			}
			result.Errors = append(result.Errors, runErr.Error())
		}
		for _, check := range report.Checks {
			if check.State == "error" || check.State == "incomplete" {
				result.Errors = append(result.Errors, check.Name+": "+check.Evidence)
			}
		}
		if err := writeADReport(o.ExportDir, &report); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
		result.Findings = app.ASREPReportFindings(report)
		saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, finding := range result.Findings {
			if err := m.store.SaveFinding(saveCtx, runID, finding); err != nil {
				status = "failed"
				return result, err
			}
		}
		return result, runErr
	}
}
