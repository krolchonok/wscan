package tui

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
	"wscan/internal/ftpclient"
)

type ftpBrowserState struct {
	options         ftpclient.Options
	credentials     []domain.Credential
	credIndex       int // 0 = anonymous, saved credentials start at 1
	directory       ftpclient.Directory
	index           int
	connected, busy bool
	cancel          context.CancelFunc
	generation      int
	preview, title  string
	offset          int
	download        *smbDownloadProgress
}
type ftpDone struct {
	generation  int
	operation   string
	directory   ftpclient.Directory
	text, title string
	err         error
}
type ftpDownloadTick struct{ generation int }

func tickFTPDownload(g int) tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(time.Time) tea.Msg { return ftpDownloadTick{g} })
}
func (m *model) prepareFTP(host string) {
	if m.ftpBrowser.cancel != nil {
		m.ftpBrowser.cancel()
	}
	target := domain.Service{Host: host, Port: 21}
	for i, s := range m.servicesFor(m.currentHost()) {
		name := strings.ToLower(s.Name)
		if name == "ftp" || name == "ftps" || name == "ftp-ssl" || (name == "" || name == "unknown") && (s.Port == 21 || s.Port == 990) {
			target = s
			if m.focusCol >= 1 && i == m.serviceIndex {
				m.interactionIndex = 4
				break
			}
		}
	}
	mode := "ftp"
	if target.Port == 990 {
		mode = "implicit"
	} else if target.Tunnel == "ssl" || target.Tunnel == "tls" || strings.Contains(strings.ToLower(target.Name), "ftps") {
		mode = "explicit"
	}
	m.ftpBrowser = ftpBrowserState{generation: m.ftpBrowser.generation + 1, options: ftpclient.Options{Host: target.Host, Port: target.Port, Mode: mode, Timeout: 30 * time.Second, Username: "anonymous", Password: "anonymous@"}}
}
func (m model) openFTPSetup() (tea.Model, tea.Cmd) {
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = "FTP: " + err.Error()
		return m, nil
	}
	m.ftpBrowser.credentials = creds
	m.ftpBrowser.credIndex = 0
	m.screen = "ftp-setup"
	m.message = ""
	return m, nil
}
func (m model) updateFTPSetup(key string) (tea.Model, tea.Cmd) {
	b := &m.ftpBrowser
	if b.busy {
		return m.updateFTPBusy(key)
	}
	switch key {
	case "esc", "q":
		b.options.Username, b.options.Password = "anonymous", "anonymous@"
		b.credentials = nil
		b.connected = false
		m.screen = "interaction-menu"
	case "up", "k":
		b.credIndex = max(0, b.credIndex-1)
	case "down", "j":
		b.credIndex = min(len(b.credentials), b.credIndex+1)
	case "s":
		switch b.options.Mode {
		case "ftp":
			b.options.Mode = "explicit"
		case "explicit":
			b.options.Mode = "implicit"
		default:
			b.options.Mode = "ftp"
		}
		if b.options.Port == 21 || b.options.Port == 990 {
			b.options.Port = 21
			if b.options.Mode == "implicit" {
				b.options.Port = 990
			}
		}
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "p":
		m.startInput("ftp-port")
		m.input = strconv.Itoa(b.options.Port)
	case "c":
		m.openCredentials()
	case "enter":
		b.options.Username, b.options.Password = "anonymous", "anonymous@"
		if b.credIndex > 0 {
			if b.credIndex > len(b.credentials) {
				return m, nil
			}
			c := b.credentials[b.credIndex-1]
			if c.Type != "password" || c.Username == "" {
				m.message = "FTP: выбери учётку с именем и паролем"
				return m, nil
			}
			b.options.Username, b.options.Password = c.Username, c.Secret
		}
		return m.startFTPOperation("connect", "", "")
	}
	return m, nil
}
func (m model) updateFTPBusy(key string) (tea.Model, tea.Cmd) {
	b := &m.ftpBrowser
	if key == "esc" {
		if b.cancel != nil {
			b.cancel()
		}
		b.generation++
		b.cancel = nil
		b.busy = false
		b.download = nil
		m.message = "FTP: операция отменена"
	}
	return m, nil
}
func (m model) startFTPOperation(operation, remote, title string) (tea.Model, tea.Cmd) {
	b := &m.ftpBrowser
	if b.busy {
		return m, nil
	}
	if operation != "connect" && !b.connected {
		m.message = "Сначала подключись к FTP"
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
	b.cancel = cancel
	b.generation++
	b.busy = true
	b.download = nil
	m.message = ""
	if operation == "download" && b.index >= 0 && b.index < len(b.directory.Entries) {
		e := b.directory.Entries[b.index]
		b.download = &smbDownloadProgress{name: e.Name, total: e.Size, started: time.Now()}
	}
	snapshot := *b
	store, project, downloadDir := m.store, m.current, filepath.Join(m.appDir, "downloads")
	cmd := func() tea.Msg {
		defer cancel()
		done := ftpDone{generation: snapshot.generation, operation: operation, title: title}
		if operation == "connect" {
			window, limit := project.LockoutWindowMinutes, project.LockoutMaxAttempts
			if window <= 0 {
				window = domain.DefaultLockoutWindowMinutes
			}
			if limit <= 0 {
				limit = domain.DefaultLockoutMaxAttempts
			}
			failures, err := store.RecentFailureCount(ctx, project.ID, snapshot.options.Username, time.Now().Add(-time.Duration(window)*time.Minute))
			if err != nil {
				done.err = err
				return done
			}
			if failures >= limit {
				done.err = fmt.Errorf("достигнут лимит ошибок входа для учётки")
				return done
			}
		}
		switch operation {
		case "connect", "list":
			done.directory, done.err = ftpclient.Browse(ctx, snapshot.options, remote)
		case "preview":
			var data bytes.Buffer
			_, done.err = ftpclient.Read(ctx, snapshot.options, remote, &data, 64*1024)
			size := int64(0)
			if snapshot.index >= 0 && snapshot.index < len(snapshot.directory.Entries) {
				size = snapshot.directory.Entries[snapshot.index].Size
			}
			done.text = smbPreview(data.Bytes(), size)
		case "download":
			var progress func(int64)
			if snapshot.download != nil {
				progress = snapshot.download.written.Store
			}
			done.text, done.err = ftpclient.Download(ctx, snapshot.options, remote, downloadDir, progress)
		}
		if operation == "connect" {
			if done.err == nil || ftpclient.AuthenticationRejected(done.err) {
				recordCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				err := store.RecordAttempt(recordCtx, project.ID, fmt.Sprintf("%s:%d", snapshot.options.Host, snapshot.options.Port), snapshot.options.Username, "ftp", done.err == nil)
				stop()
				if done.err == nil {
					done.err = err
				}
			}
		}
		return done
	}
	if operation == "download" {
		return m, tea.Batch(tickFTPDownload(snapshot.generation), cmd)
	}
	return m, cmd
}
func (m model) applyFTPDone(done ftpDone) (tea.Model, tea.Cmd) {
	b := &m.ftpBrowser
	if done.generation != b.generation || (m.screen != "ftp-setup" && m.screen != "ftp-browser") {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	b.download = nil
	if done.err != nil {
		text := done.err.Error()
		if b.options.Password != "" {
			text = strings.ReplaceAll(text, b.options.Password, "***")
		}
		m.message = "FTP: " + smbDisplayName(text)
		return m, nil
	}
	switch done.operation {
	case "connect", "list":
		b.directory = done.directory
		b.index = 0
		b.preview = ""
		b.connected = true
		m.screen = "ftp-browser"
	case "preview":
		b.preview, b.title, b.offset = done.text, done.title, 0
	case "download":
		m.message = "Скачано: " + done.text
	}
	return m, nil
}
func (m model) updateFTPBrowser(key string) (tea.Model, tea.Cmd) {
	b := &m.ftpBrowser
	if b.busy {
		return m.updateFTPBusy(key)
	}
	if b.preview != "" {
		lines := strings.Split(ansi.Wrap(b.preview, max(1, m.width-6), ""), "\n")
		switch key {
		case "esc", "backspace", "left":
			b.preview = ""
		case "down", "j":
			b.offset = min(max(0, len(lines)-1), b.offset+1)
		case "up", "k":
			b.offset = max(0, b.offset-1)
		case "pgdown":
			b.offset = min(max(0, len(lines)-1), b.offset+m.panelRows())
		case "pgup":
			b.offset = max(0, b.offset-m.panelRows())
		case "d":
			return m.downloadSelectedFTPFile()
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		b.options.Password = ""
		b.credentials = nil
		b.connected = false
		m.screen = "interaction-menu"
	case "up", "k":
		if len(b.directory.Entries) > 0 {
			b.index = (b.index + len(b.directory.Entries) - 1) % len(b.directory.Entries)
		}
	case "down", "j":
		if len(b.directory.Entries) > 0 {
			b.index = (b.index + 1) % len(b.directory.Entries)
		}
	case "left", "backspace":
		return m.startFTPOperation("list", path.Dir(b.directory.Path), "")
	case "r":
		return m.startFTPOperation("list", b.directory.Path, "")
	case "c":
		return m.openFTPSetup()
	case "p":
		m.startInput("ftp-path")
		m.input = b.directory.Path
	case "e":
		file, err := exportFTPEntries(filepath.Join(m.appDir, "downloads"), b.options.Host, b.directory)
		if err != nil {
			m.message = err.Error()
		} else {
			m.message = "Список сохранён: " + file
		}
	case "d":
		return m.downloadSelectedFTPFile()
	case "enter", "right":
		if b.index < 0 || b.index >= len(b.directory.Entries) {
			return m, nil
		}
		e := b.directory.Entries[b.index]
		remote := path.Join(b.directory.Path, e.Name)
		if e.Link != "" {
			m.message = "FTP: символическая ссылка → " + smbDisplayName(e.Link) + "; используй p для перехода по пути"
			return m, nil
		}
		if e.Directory {
			return m.startFTPOperation("list", remote, "")
		}
		return m.startFTPOperation("preview", remote, remote)
	}
	return m, nil
}
func (m model) downloadSelectedFTPFile() (tea.Model, tea.Cmd) {
	b := m.ftpBrowser
	if b.index < 0 || b.index >= len(b.directory.Entries) || b.directory.Entries[b.index].Directory || b.directory.Entries[b.index].Link != "" {
		m.message = "Выбери файл для скачивания"
		return m, nil
	}
	return m.startFTPOperation("download", path.Join(b.directory.Path, b.directory.Entries[b.index].Name), "")
}
func exportFTPEntries(directory, host string, d ftpclient.Directory) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(directory, "ftp-list-*.csv")
	if err != nil {
		return "", err
	}
	w := csv.NewWriter(f)
	err = w.Write([]string{"host", "path", "name", "directory", "size", "modified", "link"})
	for _, e := range d.Entries {
		if err != nil {
			break
		}
		modified := ""
		if !e.Modified.IsZero() {
			modified = e.Modified.Format(time.RFC3339)
		}
		err = w.Write([]string{host, path.Join(d.Path, e.Name), e.Name, strconv.FormatBool(e.Directory), strconv.FormatInt(e.Size, 10), modified, e.Link})
	}
	w.Flush()
	if err == nil {
		err = w.Error()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
func (m model) viewFTPSetup(w int) string {
	b := m.ftpBrowser
	verify := "проверять"
	if b.options.Insecure {
		verify = "не проверять"
	}
	body := headingStyle.Render("FTP — подключение") + fmt.Sprintf("\n%s:%d · %s · сертификат: %s\n\n", smbDisplayName(b.options.Host), b.options.Port, b.options.Mode, verify)
	body += renderListRow("Anonymous — anonymous / стандартный пароль", b.credIndex == 0, w)
	lo, hi := windowRange(max(0, b.credIndex-1), len(b.credentials), max(1, m.panelRows()-5))
	for i := lo; i < hi; i++ {
		c := b.credentials[i]
		body += renderListRow(smbDisplayName(credIdentLabel(c))+" · "+credTypeLabel(c.Type), b.credIndex == i+1, w)
	}
	body += "\nEnter вход · c Credentials · p порт · s FTP/FTPS · t сертификат"
	if b.busy {
		body += "\nПодключение… Esc отменить"
	}
	return m.renderPanel(w, body)
}
func (m model) viewFTPBrowser(w int) string {
	b := m.ftpBrowser
	body := headingStyle.Render("FTP — проводник") + fmt.Sprintf("\n%s:%d · %s · %s\n%s\n", smbDisplayName(b.options.Host), b.options.Port, b.options.Mode, smbDisplayName(b.options.Username), smbDisplayName(b.directory.Path))
	if b.busy {
		if b.download != nil {
			p := b.download
			written := p.written.Load()
			percent := 0.0
			if p.total > 0 {
				percent = min(100.0, float64(written)*100/float64(p.total))
			}
			speed := float64(written) / max(0.001, time.Since(p.started).Seconds())
			body += fmt.Sprintf("Скачивание %s: %.1f%% · %s / %s · %s/с · Esc отменить\n", smbDisplayName(p.name), percent, smbTransferSize(float64(written)), smbTransferSize(float64(p.total)), smbTransferSize(speed))
		} else {
			body += "Операция выполняется… Esc отменить\n"
		}
	}
	if b.preview != "" {
		body += "\n" + smbDisplayName(b.title) + "\n"
		lines := strings.Split(ansi.Wrap(b.preview, max(1, w-6), ""), "\n")
		lo := min(b.offset, max(0, len(lines)-1))
		hi := min(len(lines), lo+max(1, m.panelRows()-2))
		body += strings.Join(lines[lo:hi], "\n")
	} else {
		if b.directory.Truncated {
			body += "Показаны первые 1000 записей\n"
		}
		body += "\nИмя · размер · изменён\n"
		if len(b.directory.Entries) == 0 && !b.busy {
			body += "Пусто\n"
		}
		lo, hi := windowRange(b.index, len(b.directory.Entries), max(1, m.panelRows()-2))
		for i := lo; i < hi; i++ {
			e := b.directory.Entries[i]
			name := smbDisplayName(e.Name)
			if e.Directory {
				name = "[DIR] " + name
			}
			if e.Link != "" {
				name += " → " + smbDisplayName(e.Link)
			}
			modified := ""
			if !e.Modified.IsZero() {
				modified = e.Modified.Format("02.01.2006 15:04")
			}
			body += renderListRow(fmt.Sprintf("%s  %d B  %s", name, e.Size, modified), i == b.index, w)
		}
	}
	return m.renderPanel(w, body)
}
