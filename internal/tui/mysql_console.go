package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"strings"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

type mysqlConsoleState struct {
	options                   js.MySQLSessionOptions
	credentials               []domain.Credential
	index, offset, generation int
	session                   *js.MySQLSession
	busy                      bool
	cancel                    context.CancelFunc
	transcript                string
	browser                   sqlBrowserState
}
type mysqlDone struct {
	generation     int
	operation      string
	result         map[string]any
	page           int
	session        *js.MySQLSession
	database, text string
	err            error
}

func (m *model) closeMySQL() {
	b := &m.mysqlConsole
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
func (m model) openMySQLSetup() (tea.Model, tea.Cmd) {
	m.closeMySQL()
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = err.Error()
		return m, nil
	}
	o := js.MySQLSessionOptions{Host: m.smbBrowser.host, Port: 3306, Database: "", Username: "root", SSLMode: "true", Timeout: 30 * time.Second}
	for i, s := range m.servicesFor(m.currentHost()) {
		if s.Protocol != "udp" && domain.ServiceDatabase(s) == "MySQL / MariaDB" {
			o.Host, o.Port = s.Host, s.Port
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	m.mysqlConsole.options = o
	m.mysqlConsole.credentials = creds
	m.mysqlConsole.index = 0
	m.screen = "mysql-setup"
	m.message = ""
	return m, nil
}
func (m model) updateMySQL(key string) (tea.Model, tea.Cmd) {
	b := &m.mysqlConsole
	if b.busy {
		if key == "esc" {
			m.closeMySQL()
			m.screen = "mysql-setup"
			m.message = "Операция отменена; сессия закрыта"
		}
		return m, nil
	}
	if b.browser.mode != "" && m.screen != "mysql-setup" {
		return m.updateSQLBrowser("mysql", key)
	}
	if key == "esc" || key == "q" {
		m.closeMySQL()
		m.screen = "interaction-menu"
		return m, nil
	}
	if m.screen == "mysql-setup" {
		switch key {
		case "up", "k":
			b.index = max(0, b.index-1)
		case "down", "j":
			b.index = min(len(b.credentials), b.index+1)
		case "c":
			m.openCredentials()
		case "p":
			m.startInput("mysql-port")
			m.input = fmt.Sprint(b.options.Port)
		case "b":
			m.startInput("mysql-database")
			m.input = b.options.Database
		case "u":
			m.startInput("mysql-user")
			m.input = b.options.Username
		case "s":
			modes := []string{"true", "skip-verify", "false"}
			for i, v := range modes {
				if b.options.SSLMode == v {
					b.options.SSLMode = modes[(i+1)%len(modes)]
					break
				}
			}
		case "enter":
			b.options.Password = ""
			if b.index > 0 {
				selected := b.credentials[b.index-1]
				creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
				if err != nil {
					m.message = err.Error()
					return m, nil
				}
				found := false
				for _, c := range creds {
					if c.ID == selected.ID {
						selected = c
						found = true
						break
					}
				}
				if !found {
					m.message = "Учётка удалена; переоткрой выбор"
					return m, nil
				}
				if selected.Type != "password" {
					m.message = "Выбери учётку типа пароль"
					return m, nil
				}
				b.options.Username, b.options.Password = selected.Username, selected.Secret
			}
			return m.startMySQL("connect", b.options.Database)
		}
		return m, nil
	}
	switch key {
	case "1":
		return m.startMySQL("read", "SELECT CURRENT_USER(), USER(), DATABASE(), VERSION()")
	case "2":
		return m.startSQLBrowser("mysql", "browse-databases", 0)
	case "3", "enter":
		return m.startSQLBrowser("mysql", "browse-tables", 0)
	case "4":
		m.startInput("mysql-query")
		m.input = ":columns "
	case "5":
		m.startInput("mysql-query")
		m.input = ":rows "
	case "c":
		m.startInput("mysql-query")
	case "b":
		return m.startSQLBrowser("mysql", "browse-databases", 0)
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
func (m model) startMySQL(operation, value string) (tea.Model, tea.Cmd) {
	b := &m.mysqlConsole
	if b.busy {
		return m, nil
	}
	if operation == "query" {
		q, alias, err := mysqlReadAlias(value)
		if err != nil {
			m.message = err.Error()
			return m, nil
		}
		if alias {
			value = q
		}
	}
	if operation != "connect" && b.session == nil {
		m.message = "Подключись к MySQL / MariaDB"
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
	requestPage := b.browser.requestPage
	return m, func() tea.Msg {
		defer cancel()
		done := mysqlDone{generation: generation, operation: operation, page: requestPage}
		if operation == "connect" || operation == "database" {
			o.Database = value
			window, limit := project.LockoutWindowMinutes, project.LockoutMaxAttempts
			if window <= 0 {
				window = domain.DefaultLockoutWindowMinutes
			}
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
			session, done.err = js.OpenMySQLSession(ctx, o)
			recordCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			recordErr := store.RecordAttempt(recordCtx, project.ID, fmt.Sprintf("%s:%d", o.Host, o.Port), o.Username, "mysql", done.err == nil)
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
			done.database = o.Database
			value = "SELECT CURRENT_USER(), USER(), DATABASE(), VERSION()"
		}
		result, err := session.Read(ctx, value)
		done.err = err
		done.result = result
		if result != nil {
			done.text = "\n" + value + "\n" + mssqlTable(result)
		}
		return done
	}
}
func (m model) applyMySQLDone(done mysqlDone) (tea.Model, tea.Cmd) {
	b := &m.mysqlConsole
	if done.generation != b.generation {
		if done.session != nil {
			done.session.Close()
		}
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.session != nil {
		if b.session != nil {
			b.session.Close()
		}
		b.session = done.session
		b.options.Database = done.database
		b.browser = sqlBrowserState{}
		m.screen = "mysql-console"
		b.transcript += "\nПодключено. Режим только чтения.\n"
	}
	m.message = ""
	if done.err != nil {
		m.message = "MySQL / MariaDB: " + smbDisplayName(done.err.Error())
	}
	b.transcript += sanitizeWinRMText(done.text)
	if len(b.transcript) > 512*1024 {
		b.transcript = strings.ToValidUTF8(b.transcript[len(b.transcript)-512*1024:], "")
	}
	b.offset = 1 << 30
	if done.err == nil && strings.HasPrefix(done.operation, "browse-") {
		b.browser.apply(done.operation, done.result, done.page)
	}
	if done.err == nil && done.session != nil {
		operation := "browse-tables"
		if "mysql" == "mysql" && b.options.Database == "" {
			operation = "browse-databases"
		}
		return m.startSQLBrowser("mysql", operation, 0)
	}
	return m, nil
}
func (m model) viewMySQL(w int) string {
	b := m.mysqlConsole
	body := headingStyle.Render("MySQL / MariaDB — чтение данных") + fmt.Sprintf("\n%s:%d · база: %s · TLS: %s\n", smbDisplayName(b.options.Host), b.options.Port, smbDisplayName(b.options.Database), b.options.SSLMode)
	if m.screen == "mysql-setup" {
		body += "c учётки · p порт · b база · u пользователь без пароля · s TLS · Enter вход\n"
		body += renderListRow("Пустой пароль · пользователь: "+smbDisplayName(b.options.Username), b.index == 0, w)
		lo, hi := windowRange(max(0, b.index-1), len(b.credentials), max(1, m.panelRows()-7))
		for i := lo; i < hi; i++ {
			body += renderListRow(credIdentLabel(b.credentials[i])+" · "+credTypeLabel(b.credentials[i].Type), b.index == i+1, w)
		}
	} else if b.browser.mode != "" {
		body += b.browser.render(w, m.panelRows()-3)
	} else {
		body += "1 пользователь · Enter таблицы · b базы · c SQL только чтение\n"
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
