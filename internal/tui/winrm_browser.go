package tui

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

type winRMBrowserState struct {
	options       js.WinRMOptions
	credentials   []domain.Credential
	credIndex     int
	connected     bool
	directory     js.WinRMDirectory
	index         int
	busy          bool
	cancel        context.CancelFunc
	generation    int
	output, title string
	offset        int
	shell         *js.WinRMShell
	shellCancel   context.CancelFunc
	transcript    string
}

type winRMDone struct {
	generation      int
	operation       string
	directory       js.WinRMDirectory
	text, title     string
	err             error
	shell           *js.WinRMShell
	shellCancel     context.CancelFunc
	remoteDirectory string
}

func isWinRMService(s domain.Service) bool {
	name := strings.ToLower(s.Name + " " + s.PortService)
	return s.Port == 5985 || s.Port == 5986 || strings.Contains(name, "winrm") || strings.Contains(name, "wsman")
}

func (m *model) prepareWinRM(host string) {
	m.closeWinRMShell()
	if m.winrmBrowser.cancel != nil {
		m.winrmBrowser.cancel()
	}
	generation := m.winrmBrowser.generation + 1
	target := domain.Service{Host: host, Port: 5985}
	for i, s := range m.servicesFor(m.currentHost()) {
		if isWinRMService(s) {
			target = s
			if m.focusCol >= 1 && i == m.serviceIndex {
				m.interactionIndex = 1
				break
			}
		}
	}
	m.winrmBrowser = winRMBrowserState{generation: generation, options: js.WinRMOptions{Host: target.Host, Port: target.Port, HTTPS: target.Port == 5986 || target.Tunnel == "ssl", Timeout: 30 * time.Second}}
}

func (m model) openWinRMSetup() (tea.Model, tea.Cmd) {
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = "WinRM: " + err.Error()
		return m, nil
	}
	m.winrmBrowser.credentials = creds
	m.winrmBrowser.credIndex = 0
	m.screen = "winrm-setup"
	m.message = ""
	return m, nil
}

func (m model) updateWinRMSetup(key string) (tea.Model, tea.Cmd) {
	b := &m.winrmBrowser
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.cancel = nil
			b.busy = false
			m.message = "Подключение отменено"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		b.options.Credential = domain.Credential{}
		m.screen = "interaction-menu"
	case "up", "k":
		b.credIndex = max(0, b.credIndex-1)
	case "down", "j":
		b.credIndex = min(max(0, len(b.credentials)-1), b.credIndex+1)
	case "s":
		b.options.HTTPS = !b.options.HTTPS
		if b.options.Port == 5985 || b.options.Port == 5986 {
			if b.options.HTTPS {
				b.options.Port = 5986
			} else {
				b.options.Port = 5985
			}
		}
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "p":
		m.startInput("winrm-port")
		m.input = strconv.Itoa(b.options.Port)
	case "c":
		m.openCredentials()
	case "enter":
		if b.credIndex >= len(b.credentials) {
			m.message = "Добавь учётку: c → a, затем вернись в Взаимодействие → WinRM"
			return m, nil
		}
		cred := b.credentials[b.credIndex]
		if cred.Type != "password" || cred.Username == "" {
			m.message = "Для WinRM выбери учётку с именем и паролем; NTLM-хеш пока не поддерживается"
			return m, nil
		}
		b.options.Credential = cred
		return m.startWinRMOperation("connect", "", "")
	}
	return m, nil
}

func (m model) startWinRMOperation(operation, value, title string) (tea.Model, tea.Cmd) {
	b := &m.winrmBrowser
	if b.busy {
		return m, nil
	}
	if operation != "connect" && !b.connected {
		m.message = "Сначала подключись к WinRM"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := 2 * time.Minute
	if operation == "download" {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	b.generation++
	b.cancel = cancel
	b.busy = true
	m.message = ""
	options, generation := b.options, b.generation
	directory := b.directory.Path
	downloadDir := filepath.Join(m.appDir, "downloads")
	store, project := m.store, m.current
	appCtx := m.ctx
	if appCtx == nil {
		appCtx = context.Background()
	}
	shell := b.shell
	return m, func() tea.Msg {
		defer cancel()
		done := winRMDone{generation: generation, operation: operation, title: title}
		switch operation {
		case "connect":
			maxAttempts, window := project.LockoutMaxAttempts, project.LockoutWindowMinutes
			if maxAttempts <= 0 {
				maxAttempts = domain.DefaultLockoutMaxAttempts
			}
			if window <= 0 {
				window = domain.DefaultLockoutWindowMinutes
			}
			n, err := store.RecentFailureCount(ctx, project.ID, options.Credential.Username, time.Now().Add(-time.Duration(window)*time.Minute))
			if err != nil {
				done.err = err
				break
			}
			if n >= maxAttempts {
				done.err = fmt.Errorf("учётка временно заблокирована для повторных попыток: %d ошибок за %d мин", n, window)
				break
			}
			done.text, done.err = js.WinRMIdentity(ctx, options)
			recordCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			recordErr := store.RecordAttempt(recordCtx, project.ID, options.Host, options.Credential.Username, "winrm", done.err == nil)
			stop()
			if done.err == nil && recordErr != nil {
				done.err = fmt.Errorf("не удалось сохранить результат входа: %w", recordErr)
			}
			done.title = "Пользователь, группы и привилегии"
		case "list":
			done.directory, done.err = js.BrowseWinRM(ctx, options, value)
		case "identity":
			done.text, done.err = js.WinRMIdentity(ctx, options)
		case "preview":
			var data bytes.Buffer
			_, done.err = js.ReadWinRMFile(ctx, options, value, &data, 64*1024)
			size := int64(data.Len())
			if data.Len() == 64*1024 {
				size++
			}
			done.text = smbPreview(data.Bytes(), size)
		case "download":
			done.text, done.err = js.DownloadWinRM(ctx, options, value, downloadDir)
		case "shell-open":
			shellCtx, shellCancel := context.WithTimeout(appCtx, time.Hour)
			stop := context.AfterFunc(ctx, shellCancel)
			session, err := js.OpenWinRMShell(shellCtx, options, directory)
			stop()
			if err != nil {
				shellCancel()
				done.err = err
				break
			}
			response, err := session.Run(ctx, "'PowerShell подключён'; Get-Location")
			if err != nil {
				session.Close()
				time.AfterFunc(3*time.Second, shellCancel)
				done.err = err
				break
			}
			done.shell, done.shellCancel = session, shellCancel
			done.text, done.remoteDirectory = response.Output, response.Directory
		case "shell-command":
			if shell == nil {
				done.err = fmt.Errorf("PowerShell-сессия закрыта")
				break
			}
			response, err := shell.Run(ctx, value)
			done.err = err
			done.text = fmt.Sprintf("PS> %s\n%s\nКод: %d\n", value, response.Output, response.ExitCode)
			done.remoteDirectory = response.Directory
		case "command":
			script := "Set-Location -LiteralPath " + winRMPSLiteral(directory) + "; " + value
			out, stderr, code, err := js.RunWinRMPowerShell(ctx, options, script, 256*1024)
			done.err = err
			done.text = fmt.Sprintf("Код завершения: %d\n\n%s", code, out)
			if stderr != "" {
				done.text += "\n\nSTDERR:\n" + stderr
			}
		}
		return done
	}
}

func winRMPSLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func (m model) applyWinRMDone(done winRMDone) (tea.Model, tea.Cmd) {
	b := &m.winrmBrowser
	if b.generation != done.generation {
		if done.shell != nil {
			done.shell.Close()
			time.AfterFunc(3*time.Second, done.shellCancel)
		}
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.err != nil {
		if done.operation == "shell-command" {
			m.closeWinRMShell()
			m.screen = "winrm-browser"
		}
		m.message = "WinRM: " + smbDisplayName(done.err.Error())
		return m, nil
	}
	switch done.operation {
	case "shell-open":
		b.shell, b.shellCancel = done.shell, done.shellCancel
		b.transcript = sanitizeWinRMText(done.text)
		b.offset = 0
		m.screen = "winrm-shell"
	case "shell-command":
		b.transcript += "\n" + sanitizeWinRMText(done.text)
		if len(b.transcript) > 512*1024 {
			b.transcript = strings.ToValidUTF8(b.transcript[len(b.transcript)-512*1024:], "")
		}
		if done.remoteDirectory != "" {
			b.directory.Path = done.remoteDirectory
		}
		b.offset = 1 << 30
	case "connect":
		b.connected = true
		b.title, b.output = done.title, sanitizeWinRMText(done.text)
		b.offset = 0
		m.screen = "winrm-browser"
		return m.startWinRMOperation("list", "", "")
	case "list":
		b.directory = done.directory
		b.index = 0
	case "download":
		m.message = "Скачано: " + smbDisplayName(done.text)
	default:
		b.title, b.output = done.title, sanitizeWinRMText(done.text)
		b.offset = 0
	}
	return m, nil
}

func (m model) updateWinRMBrowser(key string) (tea.Model, tea.Cmd) {
	b := &m.winrmBrowser
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.cancel = nil
			b.busy = false
			m.message = "Операция отменена"
		}
		return m, nil
	}
	if b.output != "" {
		switch key {
		case "esc", "q", "left":
			b.output = ""
			b.offset = 0
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
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		b.connected = false
		b.options.Credential = domain.Credential{}
		b.credentials = nil
		m.screen = "interaction-menu"
	case "up", "k":
		b.index = max(0, b.index-1)
	case "down", "j":
		b.index = min(max(0, len(b.directory.Entries)-1), b.index+1)
	case "home":
		b.index = 0
	case "end":
		b.index = max(0, len(b.directory.Entries)-1)
	case "left", "backspace":
		if b.directory.Parent != "" {
			return m.startWinRMOperation("list", b.directory.Parent, "")
		}
	case "r":
		return m.startWinRMOperation("list", b.directory.Path, "")
	case "p":
		m.startInput("winrm-path")
		m.input = b.directory.Path
	case "s":
		return m.startWinRMOperation("shell-open", "", "")
	case "c":
		m.startInput("winrm-command")
	case "u":
		return m.startWinRMOperation("identity", "", "Пользователь, группы и привилегии")
	case "e":
		path, err := exportWinRMDirectory(filepath.Join(m.appDir, "downloads"), b.options.Host, b.directory)
		if err != nil {
			m.message = err.Error()
		} else {
			m.message = "Список сохранён: " + path
		}
	case "enter", "d", "a":
		if b.index >= len(b.directory.Entries) {
			return m, nil
		}
		entry := b.directory.Entries[b.index]
		if key == "a" {
			b.title = entry.Name + " — ACL"
			b.output = sanitizeWinRMText("Владелец: " + entry.Owner + "\n\n" + entry.Rights + "\n" + entry.AccessError)
			b.offset = 0
			return m, nil
		}
		if entry.Directory {
			if key == "enter" {
				return m.startWinRMOperation("list", entry.Path, "")
			}
			m.message = "Выбери файл для скачивания"
			return m, nil
		}
		if key == "d" {
			return m.startWinRMOperation("download", entry.Path, entry.Name)
		}
		return m.startWinRMOperation("preview", entry.Path, entry.Name)
	}
	return m, nil
}

func sanitizeWinRMText(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 && !(r >= 0x80 && r <= 0x9f) {
			return r
		}
		return -1
	}, strings.ReplaceAll(value, "\r\n", "\n"))
}

func (m model) viewWinRMSetup(w int) string {
	b := m.winrmBrowser
	scheme := "HTTP"
	if b.options.HTTPS {
		scheme = "HTTPS"
	}
	body := headingStyle.Render("WinRM — подключение") + fmt.Sprintf("\n%s://%s:%d/wsman\n", strings.ToLower(scheme), b.options.Host, b.options.Port)
	if b.options.HTTPS {
		body += fmt.Sprintf("Проверка сертификата: %s\n", map[bool]string{true: "выключена", false: "включена"}[b.options.Insecure])
	}
	body += "\nВыбери одну сохранённую учётку. Пароль не отображается.\n"
	lo, hi := windowRange(b.credIndex, len(b.credentials), max(1, m.panelRows()-6))
	for i := lo; i < hi; i++ {
		cred := b.credentials[i]
		body += renderListRow(credIdentLabel(cred)+" · "+credTypeLabel(cred.Type), i == b.credIndex, w)
	}
	if len(b.credentials) == 0 {
		body += "Нет учёток. c — открыть Credentials, a — добавить.\n"
	}
	if b.busy {
		body += "\nПодключение… Esc — отменить"
	}
	return m.renderPanel(w, body)
}

func (m model) viewWinRMBrowser(w int) string {
	b := m.winrmBrowser
	body := headingStyle.Render("WinRM — "+smbDisplayName(credIdentLabel(b.options.Credential))) + fmt.Sprintf("\n%s:%d · %s\n", b.options.Host, b.options.Port, smbDisplayName(b.directory.Path))
	if b.busy {
		body += "Операция выполняется… Esc — отменить\n"
	}
	if b.output != "" {
		body += "\n" + smbDisplayName(b.title) + "\n"
		lines := strings.Split(ansi.Wrap(b.output, max(1, w-6), ""), "\n")
		lo := min(b.offset, max(0, len(lines)-1))
		hi := min(len(lines), lo+max(1, m.panelRows()-4))
		body += strings.Join(lines[lo:hi], "\n")
		return m.renderPanel(w, body)
	}
	body += "Имя                          Размер / дата          ACL → a подробно\n"
	lo, hi := windowRange(b.index, len(b.directory.Entries), max(1, m.panelRows()-6))
	for i := lo; i < hi; i++ {
		e := b.directory.Entries[i]
		name := smbDisplayName(e.Name)
		if e.Directory {
			name = "📁 " + name
		}
		name = ansi.Truncate(name, max(8, (w-8)/3), "…")
		rights := winRMACLSummary(e.Rights)
		if e.AccessError != "" {
			rights = "ACL ?"
		}
		if rights == "" {
			rights = "—"
		}
		rights = ansi.Truncate(smbDisplayName(rights), max(8, (w-8)/3), "…")
		usable := max(1, w-8)
		left := ansi.Truncate(fmt.Sprintf("%s  %d  %s", name, e.Size, e.Modified), max(1, usable-ansi.StringWidth(rights)-2), "…")
		line := left + strings.Repeat(" ", max(2, usable-ansi.StringWidth(left)-ansi.StringWidth(rights))) + rights
		body += renderListRow(line, i == b.index, w)
	}
	if b.index < len(b.directory.Entries) {
		e := b.directory.Entries[b.index]
		body += "\nВладелец: " + smbDisplayName(e.Owner)
	}
	if b.directory.Truncated {
		body += "\nПоказаны первые 1000 записей"
	}
	return m.renderPanel(w, body)
}

func exportWinRMDirectory(directory, host string, listing js.WinRMDirectory) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, "winrm-list-*.csv")
	if err != nil {
		return "", err
	}
	writer := csv.NewWriter(file)
	err = writer.Write([]string{"host", "path", "name", "directory", "size", "modified", "owner", "acl", "access_error"})
	if err == nil {
		for _, e := range listing.Entries {
			if err = writer.Write([]string{host, e.Path, e.Name, strconv.FormatBool(e.Directory), strconv.FormatInt(e.Size, 10), e.Modified, e.Owner, e.Rights, e.AccessError}); err != nil {
				break
			}
		}
	}
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func (m *model) closeWinRMShell() {
	b := &m.winrmBrowser
	if b.shell != nil {
		b.shell.Close()
		b.shell = nil
	}
	if b.shellCancel != nil {
		time.AfterFunc(3*time.Second, b.shellCancel)
		b.shellCancel = nil
	}
}

func (m model) updateWinRMShell(key string) (tea.Model, tea.Cmd) {
	b := &m.winrmBrowser
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.cancel = nil
			b.busy = false
			m.closeWinRMShell()
			m.screen = "winrm-browser"
			m.message = "Команда отменена, PowerShell-сессия закрыта"
		}
		return m, nil
	}
	if b.offset > 1<<20 {
		lines := strings.Split(ansi.Wrap(b.transcript, max(1, m.width-6), ""), "\n")
		b.offset = max(0, len(lines)-max(1, m.panelRows()-4))
	}
	switch key {
	case "esc", "q":
		m.closeWinRMShell()
		m.screen = "winrm-browser"
		return m.startWinRMOperation("list", b.directory.Path, "")
	case "enter", "c":
		m.startInput("winrm-shell-command")
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

func (m model) viewWinRMShell(w int) string {
	b := m.winrmBrowser
	body := headingStyle.Render("WinRM — PowerShell-сессия") + "\n" + smbDisplayName(b.directory.Path) + "\n"
	if b.busy {
		body += "Команда выполняется… Esc — отменить и закрыть сессию\n"
	}
	lines := strings.Split(ansi.Wrap(b.transcript, max(1, w-6), ""), "\n")
	count := max(1, m.panelRows()-4)
	lo := min(b.offset, max(0, len(lines)-count))
	body += strings.Join(lines[lo:min(len(lines), lo+count)], "\n")
	return m.renderPanel(w, body)
}

func winRMACLSummary(acl string) string {
	var rights []string
	seen := map[string]bool{}
	for _, entry := range strings.Split(acl, ";") {
		if at := strings.LastIndex(entry, ":"); at >= 0 {
			entry = entry[at+1:]
		}
		entry = strings.TrimSpace(entry)
		if entry != "" && !seen[entry] {
			rights = append(rights, entry)
			seen[entry] = true
		}
	}
	return strings.Join(rights, "; ")
}
