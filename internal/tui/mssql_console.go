package tui

import (
	"context"
	"encoding/json"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"path/filepath"
	"strings"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
	"wscan/internal/nse"
)

type mssqlConsoleState struct {
	options                                                                 js.MSSQLOptions
	credentials                                                             []domain.Credential
	index, offset, generation                                               int
	actionIndex                                                             int
	transferLocal, transferAddress, transferRemote, winpeasPath, reportPath string
	transferPort, reportOffset                                              int
	session                                                                 *js.MSSQLSession
	busy                                                                    bool
	cancel                                                                  context.CancelFunc
	transcript                                                              string
}
type mssqlDone struct {
	generation      int
	session         *js.MSSQLSession
	text            string
	transferredPath string
	err             error
}

func (m *model) closeMSSQL() {
	b := &m.mssqlConsole
	if b.cancel != nil {
		b.cancel()
	}
	if b.session != nil {
		b.session.Close()
		b.session = nil
	}
	b.generation++
	b.busy = false
	b.options.Password = ""
}
func (m model) openMSSQLSetup() (tea.Model, tea.Cmd) {
	m.closeMSSQL()
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = err.Error()
		return m, nil
	}
	o := js.MSSQLOptions{Host: m.smbBrowser.host, Port: 1433, Encrypt: true, Timeout: 30 * time.Second}
	for i, s := range m.servicesFor(m.currentHost()) {
		if s.Protocol != "udp" && (strings.Contains(strings.ToLower(s.Name+" "+s.PortService), "mssql") || strings.Contains(strings.ToLower(s.Name+" "+s.PortService), "ms-sql") || s.Port == 1433) {
			o.Host, o.Port = s.Host, s.Port
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	m.mssqlConsole.options = o
	m.mssqlConsole.credentials = creds
	m.mssqlConsole.index = 0
	m.screen = "mssql-setup"
	m.message = ""
	return m, nil
}
func (m model) updateMSSQL(key string) (tea.Model, tea.Cmd) {
	b := &m.mssqlConsole
	if m.screen == "mssql-actions" || m.screen == "mssql-xp-confirm" {
		return m.updateMSSQLActions(key)
	}
	if b.busy {
		if key == "esc" {
			m.closeMSSQL()
			m.screen = "mssql-setup"
			m.message = "Операция отменена; SQL-сессия закрыта"
		}
		return m, nil
	}
	if m.screen == "mssql-setup" {
		switch key {
		case "esc", "q":
			m.closeMSSQL()
			m.screen = "interaction-menu"
		case "up", "k":
			b.index = max(0, b.index-1)
		case "down", "j":
			b.index = min(max(0, len(b.credentials)-1), b.index+1)
		case "c":
			m.openCredentials()
		case "p":
			m.startInput("mssql-port")
			m.input = fmt.Sprint(b.options.Port)
		case "t":
			b.options.TrustServerCertificate = !b.options.TrustServerCertificate
		case "s":
			b.options.Encrypt = !b.options.Encrypt
		case "enter":
			if b.index >= len(b.credentials) {
				m.message = "c → a: добавь учётку"
				return m, nil
			}
			cred := b.credentials[b.index]
			// Read the selected record again: credentials may have been edited
			// while this setup screen retained its previous snapshot.
			creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
			if err != nil {
				m.message = "MSSQL: " + err.Error()
				return m, nil
			}
			found := false
			for _, current := range creds {
				if current.ID == cred.ID {
					cred, found = current, true
					break
				}
			}
			if !found {
				m.message = "MSSQL: учётка удалена; переоткрой выбор учётки"
				return m, nil
			}
			b.credentials = creds
			if cred.Type != "password" {
				m.message = "MSSQL: выбери учётку с паролем"
				return m, nil
			}
			b.options.Username, b.options.Password, b.options.Domain = cred.Username, cred.Secret, cred.Domain
			return m.startMSSQL("connect", "")
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.closeMSSQL()
		m.screen = "interaction-menu"
	case "enter", "m":
		m.screen = "mssql-actions"
	case "c":
		m.startInput("mssql-query")
	case "n":
		m.startInput("mssql-nse")
		m.input = "ms-sql-info"
	case "b":
		m.startInput("mssql-database")
	case "1":
		return m.startMSSQL("audit", "identity")
	case "2":
		return m.startMSSQL("audit", "permissions")
	case "3":
		return m.startMSSQL("audit", "databases")
	case "4":
		return m.startMSSQL("audit", "tables")
	case "5":
		return m.startMSSQL("audit", "columns")
	case "6":
		return m.startMSSQL("audit", "configuration")
	case "7":
		return m.startMSSQL("audit", "impersonate")
	case "8":
		return m.startMSSQL("audit", "linked-servers")
	case "up", "k":
		b.offset = max(0, b.offset-1)
	case "down", "j":
		b.offset++
	case "pgup":
		b.offset = max(0, b.offset-10)
	case "pgdown":
		b.offset += 10
	case "home":
		b.offset = 0
	case "end":
		b.offset = 1 << 30
	}
	return m, nil
}
func (m model) startMSSQL(operation, value string) (tea.Model, tea.Cmd) {
	b := &m.mssqlConsole
	if b.busy {
		return m, nil
	}
	if operation == "query" {
		query, alias, err := mssqlReadAlias(value)
		if err != nil {
			m.message = err.Error()
			return m, nil
		}
		if alias {
			operation, value = "read", query
		}
	}
	if (operation == "query" || operation == "transfer" || operation == "winpeas" || operation == "report") && !m.current.AllowExploit {
		m.message = "Произвольный SQL требует AllowExploit"
		return m, nil
	}
	if operation != "connect" && b.session == nil {
		m.message = "Подключись к MSSQL"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	b.cancel = cancel
	b.busy = true
	b.generation++
	generation, o, session := b.generation, b.options, b.session
	store, project := m.store, m.current
	runner, libraryDir := m.nseRunner(), m.cat.LibraryDir()
	return m, func() tea.Msg {
		defer cancel()
		done := mssqlDone{generation: generation}
		if operation == "connect" {
			window := project.LockoutWindowMinutes
			if window <= 0 {
				window = domain.DefaultLockoutWindowMinutes
			}
			limit := project.LockoutMaxAttempts
			if limit <= 0 {
				limit = domain.DefaultLockoutMaxAttempts
			}
			n, err := store.RecentFailureCount(ctx, project.ID, o.Username, time.Now().Add(-time.Duration(window)*time.Minute))
			if err != nil {
				done.err = err
				return done
			}
			if n >= limit {
				done.err = fmt.Errorf("достигнут лимит ошибок входа для учётки")
				return done
			}
			session, done.err = js.OpenMSSQL(ctx, o)
			recordCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			recordErr := store.RecordAttempt(recordCtx, project.ID, fmt.Sprintf("%s:%d", o.Host, o.Port), o.Username, "mssql", done.err == nil)
			stop()
			if done.err != nil {
				return done
			}
			if recordErr != nil {
				session.Close()
				done.err = recordErr
				return done
			}
			done.session = session
			operation, value = "audit", "identity"
		}
		if operation == "nse" {
			allowed := map[string]bool{"ms-sql-info": true, "ms-sql-hasdbaccess": true, "ms-sql-tables": true}
			if !allowed[value] {
				done.err = fmt.Errorf("доступны ms-sql-info, ms-sql-hasdbaccess, ms-sql-tables")
				return done
			}
			args := map[string]string{"mssql.username": o.Username, "mssql.password": o.Password, "mssql.scanned-ports-only": "true", "mssql.instance-port": fmt.Sprint(o.Port)}
			if o.Domain != "" {
				args["mssql.domain"] = o.Domain
			}
			results, ran, err := runner.RunWithArgs(ctx, filepath.Join(libraryDir, "nmap", "scripts", value+".nse"), nse.HostInfo{IP: o.Host}, []nse.PortInfo{{Number: o.Port, Protocol: "tcp", Service: "ms-sql-s", State: "open"}}, args)
			done.err = err
			if !ran && err == nil {
				done.err = fmt.Errorf("NSE: правило не подошло или движок не выполнил скрипт")
			}
			for _, result := range results {
				done.text += result.ScriptID + "\n" + result.Output + "\n"
			}
			return done
		}
		var result map[string]any
		if operation == "transfer" {
			server, err := js.StartPythonFileServer(ctx, b.transferLocal, b.transferAddress, b.transferPort)
			if err != nil {
				done.err = err
				return done
			}
			defer server.Close()
			done.text = "HTTP: " + server.URL + "\n"
			query := mssqlPowerShellQuery(mssqlDownloadScript(server.URL, b.transferRemote, server.SHA256))
			result, done.err = session.Query(ctx, query)
			if result != nil {
				done.text += mssqlTable(result)
			}
			if done.err == nil {
				if mssqlResultHasMarker(result, "TRANSFER_OK ") {
					done.transferredPath = b.transferRemote
				} else {
					done.err = fmt.Errorf("передача не подтверждена Windows; подробности в выводе")
				}
			}
			return done
		}
		if operation == "audit" {
			result, done.err = session.Audit(ctx, value)
		} else {
			query := value
			if operation == "database" {
				query = "USE [" + strings.ReplaceAll(value, "]", "]]") + "]; SELECT DB_NAME() AS current_database"
			}
			result, done.err = session.Query(ctx, query)
		}
		if result != nil {
			done.text = "\n" + operation + " " + value + "\n" + mssqlTable(result)
		}
		if operation == "winpeas" && done.err == nil && !mssqlResultHasMarker(result, "WINPEAS_PID ") {
			done.err = fmt.Errorf("запуск WinPEAS не подтверждён; подробности в выводе")
		}
		return done
	}
}
func mssqlTable(result map[string]any) string {
	sets, ok := result["ResultSets"].([]map[string]any)
	if !ok {
		b, _ := json.MarshalIndent(result, "", "  ")
		return string(b)
	}
	var out strings.Builder
	for _, set := range sets {
		cols := set["Columns"].([]string)
		out.WriteString(strings.Join(cols, " | ") + "\n")
		for _, row := range set["Rows"].([][]any) {
			parts := []string{}
			for _, v := range row {
				if v == nil {
					parts = append(parts, "NULL")
				} else {
					parts = append(parts, sanitizeWinRMText(fmt.Sprint(v)))
				}
			}
			out.WriteString(strings.Join(parts, " | ") + "\n")
		}
		out.WriteString(fmt.Sprintf("Строк: %v; ограничено: %v\n", set["Count"], set["Truncated"]))
	}
	return out.String()
}
func (m model) applyMSSQLDone(done mssqlDone) (tea.Model, tea.Cmd) {
	b := &m.mssqlConsole
	if b.generation != done.generation {
		if done.session != nil {
			done.session.Close()
		}
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.transferredPath != "" {
		b.winpeasPath = done.transferredPath
		b.reportPath = done.transferredPath + ".txt"
		b.reportOffset = 0
	}
	if done.session != nil {
		b.session = done.session
		m.screen = "mssql-console"
		b.transcript = "Подключено к выбранному MSSQL-сервису. SQL-сессия сохраняется.\n"
	}
	if done.err != nil {
		m.message = "MSSQL: " + smbDisplayName(done.err.Error())
	} else {
		m.message = ""
	}
	b.transcript += sanitizeWinRMText(done.text)
	if len(b.transcript) > 512*1024 {
		b.transcript = strings.ToValidUTF8(b.transcript[len(b.transcript)-512*1024:], "")
	}
	b.offset = 1 << 30
	return m, nil
}
func (m model) viewMSSQL(w int) string {
	b := m.mssqlConsole
	body := headingStyle.Render("MSSQL — SQL-консоль") + fmt.Sprintf("\n%s:%d · TLS: %t · проверка сертификата: %t\n", b.options.Host, b.options.Port, b.options.Encrypt, !b.options.TrustServerCertificate)
	if m.screen == "mssql-setup" {
		body += "Одна учётка: SQL login либо Windows при заполненном Domain.\n"
		lo, hi := windowRange(b.index, len(b.credentials), max(1, m.panelRows()-5))
		for i := lo; i < hi; i++ {
			body += renderListRow(credIdentLabel(b.credentials[i])+" · "+credTypeLabel(b.credentials[i].Type), i == b.index, w)
		}
		body += "\nEnter вход · c учётки · p порт · s TLS · t доверять сертификату"
	} else {
		body += "1 пользователь · 2 права · 3 базы · 4 таблицы · 5 столбцы\n6 настройки · 7 IMPERSONATE · 8 linked servers\nb база · n NSE с выбранной учёткой · Enter меню · c SQL / алиасы · Esc закрыть\n"
		body += ":db · :tables · :columns dbo.table · :rows dbo.table [100] · :count dbo.table\n"
		lines := strings.Split(ansi.Wrap(b.transcript, max(1, w-6), ""), "\n")
		count := max(1, m.panelRows()-7)
		lo := min(b.offset, max(0, len(lines)-count))
		body += strings.Join(lines[lo:min(len(lines), lo+count)], "\n")
	}
	if b.busy {
		body += "\nВыполняется… Esc — отменить"
	}
	return m.renderPanel(w, body)
}
