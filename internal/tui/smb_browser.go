package tui

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

type smbBrowserState struct {
	credential       domain.Credential
	credentials      []domain.Credential
	credIndex        int
	host             string
	port             int
	mode             string
	share, directory string
	entries          []js.SMBEntry
	index            int
	busy             bool
	cancel           context.CancelFunc
	generation       int
	preview          string
	previewTitle     string
	offset           int
	download         *smbDownloadProgress
}

type smbDownloadProgress struct {
	name    string
	total   int64
	written atomic.Int64
	started time.Time
}

type smbDownloadTick struct{ generation int }

func tickSMBDownload(generation int) tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(time.Time) tea.Msg { return smbDownloadTick{generation} })
}

func (m model) applySMBDownloadTick(tick smbDownloadTick) (tea.Model, tea.Cmd) {
	if tick.generation != m.smbBrowser.generation || !m.smbBrowser.busy || m.screen != "smb-browser" || m.smbBrowser.download == nil {
		return m, nil
	}
	return m, tickSMBDownload(tick.generation)
}

type smbBrowserDone struct {
	generation       int
	operation        string
	share, directory string
	entries          []js.SMBEntry
	text             string
	err              error
}

func (m *model) openInteractionMenu() {
	host := m.currentHost()
	normalized := host
	if host != "" {
		var err error
		normalized, err = discovery.TargetHost(host)
		if err != nil {
			m.message = err.Error()
			return
		}
	}
	m.interactionReturn = "desk"
	port := 445
	for i, s := range m.servicesFor(host) {
		if s.Port == 445 || (m.focusCol >= 1 && i == m.serviceIndex && strings.EqualFold(s.Name, "smb")) {
			normalized, port = s.Host, s.Port
			if i == m.serviceIndex {
				break
			}
		}
	}
	if m.smbBrowser.cancel != nil {
		m.smbBrowser.cancel()
	}
	generation := m.smbBrowser.generation + 1
	m.smbBrowser = smbBrowserState{host: normalized, port: port, mode: "guest", generation: generation}
	m.interactionIndex = 0
	m.prepareWinRM(normalized)
	m.prepareFTP(normalized)
	if services := m.servicesFor(host); m.focusCol >= 1 && m.serviceIndex >= 0 && m.serviceIndex < len(services) && domain.ServiceDatabase(services[m.serviceIndex]) == "PostgreSQL" {
		m.interactionIndex = 5
	}
	if services := m.servicesFor(host); m.focusCol >= 1 && m.serviceIndex >= 0 && m.serviceIndex < len(services) && domain.ServiceDatabase(services[m.serviceIndex]) == "MySQL / MariaDB" {
		m.interactionIndex = 6
	}
	if services := m.servicesFor(host); m.focusCol >= 1 && m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		if _, ok := discovery.WebURL(services[m.serviceIndex]); ok {
			m.interactionIndex = 7
		}
	}
	if services := m.servicesFor(host); m.focusCol >= 1 && m.serviceIndex >= 0 && m.serviceIndex < len(services) && strings.Contains(strings.ToLower(services[m.serviceIndex].Name+" "+services[m.serviceIndex].PortService), "ssh") {
		m.interactionIndex = 8
	}
	m.kyoceraBook.target = domain.Service{Host: normalized, Port: 9091, Protocol: "tcp", Name: "kyocera", Tunnel: "ssl"}
	for i, s := range m.servicesFor(host) {
		if serviceIsKyocera(s) {
			m.kyoceraBook.target = s
			if m.focusCol >= 1 && i == m.serviceIndex {
				m.interactionIndex = 11
				break
			}
		}
	}
	m.screen = "interaction-menu"
	m.message = ""
}

func (m model) updateInteractionMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = m.interactionReturn
		if m.screen == "" || m.screen == "interaction-menu" {
			m.screen = "desk"
		}
	case "h":
		m.interactionHostIndex = 0
		m.screen = "interaction-targets"
	case "up", "k":
		m.interactionIndex = (m.interactionIndex + interactionMenuCount - 1) % interactionMenuCount
	case "down", "j", "tab":
		m.interactionIndex = (m.interactionIndex + 1) % interactionMenuCount
	case "enter":
		if m.interactionIndex == 13 {
			return m.openNSEVuln()
		}
		if m.interactionIndex == 12 {
			return m.openVersionCVE()
		}
		if m.interactionIndex == 7 {
			return m.openWebDiscovery()
		}
		if m.interactionIndex == 9 {
			return m.openSQLiForm()
		}
		if m.interactionIndex == 10 {
			return m.openFileUpload()
		}
		if m.interactionIndex == 11 {
			return m.openKyoceraSetup()
		}
		if m.smbBrowser.host == "" {
			m.message = "h — выбери хост"
			return m, nil
		}
		if m.interactionIndex == 8 {
			return m.openSSHDictionary()
		}
		if m.interactionIndex == 6 {
			return m.openMySQLSetup()
		}
		if m.interactionIndex == 5 {
			return m.openPGSetup()
		}
		if m.interactionIndex == 4 {
			return m.openFTPSetup()
		}
		if m.interactionIndex == 2 {
			return m.openMSSQLSetup()
		}
		if m.interactionIndex == 3 {
			return m.openLFISetup()
		}
		if m.interactionIndex == 1 {
			return m.openWinRMSetup()
		}
		m.screen = "smb-browser"
		return m.loadSMBDirectory("", "")
	}
	return m, nil
}

func (m model) beginSMBOperation() (model, context.Context) {
	m.smbBrowser.generation++
	m.smbBrowser.busy = true
	m.smbBrowser.download = nil
	m.message = ""
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithCancel(ctx)
	m.smbBrowser.cancel = cancel
	return m, operationCtx
}

func (m model) loadSMBDirectory(share, directory string) (tea.Model, tea.Cmd) {
	m, ctx := m.beginSMBOperation()
	b := m.smbBrowser
	return m, func() tea.Msg {
		defer b.cancel()
		entries, err := js.BrowseSMBWithOptions(ctx, b.options(), share, directory)
		return smbBrowserDone{generation: b.generation, operation: "list", share: share, directory: directory, entries: entries, err: err}
	}
}

func (m model) applySMBBrowserDone(done smbBrowserDone) (tea.Model, tea.Cmd) {
	if done.generation != m.smbBrowser.generation || m.screen != "smb-browser" {
		return m, nil
	}
	m.smbBrowser.busy = false
	m.smbBrowser.cancel = nil
	if done.err != nil {
		m.message = "SMB: " + done.err.Error()
		return m, nil
	}
	switch done.operation {
	case "list":
		m.smbBrowser.share, m.smbBrowser.directory = done.share, done.directory
		m.smbBrowser.entries, m.smbBrowser.index = done.entries, 0
		m.smbBrowser.preview = ""
	case "configs":
		m.smbBrowser.preview, m.smbBrowser.previewTitle = done.text, "Конфигурации: секреты скрыты"
		m.smbBrowser.offset = 0
	case "preview":
		m.smbBrowser.preview, m.smbBrowser.previewTitle = done.text, done.directory
		m.smbBrowser.offset = 0
	case "download":
		m.message = "Скачано: " + done.text
	}
	return m, nil
}

func (m model) updateSMBBrowser(key string) (tea.Model, tea.Cmd) {
	b := &m.smbBrowser
	if b.busy {
		if key == "esc" && b.cancel != nil {
			b.cancel()
			b.generation++
			b.busy = false
			b.cancel = nil
			m.message = "Операция отменена"
		}
		return m, nil
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
			return m.downloadSelectedSMBFile()
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		b.credential = domain.Credential{}
		b.credentials = nil
		b.mode = "guest"
		m.screen = "interaction-menu"
	case "up", "k":
		if len(b.entries) > 0 {
			b.index = (b.index + len(b.entries) - 1) % len(b.entries)
		}
	case "down", "j":
		if len(b.entries) > 0 {
			b.index = (b.index + 1) % len(b.entries)
		}
	case "backspace", "left":
		if b.share != "" {
			if b.directory == "" || b.directory == "." {
				return m.loadSMBDirectory("", "")
			}
			parent := path.Dir(b.directory)
			if parent == "." {
				parent = ""
			}
			return m.loadSMBDirectory(b.share, parent)
		}
	case "p":
		m.startInput("smb-port")
		m.input = strconv.Itoa(b.port)
	case "c":
		return m.openSMBCredentials()
	case "a":
		b.credential = domain.Credential{}
		if b.mode == "null" {
			b.mode = "guest"
		} else {
			b.mode = "null"
		}
		return m.loadSMBDirectory("", "")
	case "f":
		if b.share == "" {
			m.message = "Выбери файловую шару"
			return m, nil
		}
		m, ctx := m.beginSMBOperation()
		snapshot := m.smbBrowser
		return m, func() tea.Msg {
			defer snapshot.cancel()
			report, err := js.FindSMBConfigs(ctx, snapshot.options(), snapshot.share, snapshot.directory)
			data, _ := json.MarshalIndent(report, "", "  ")
			return smbBrowserDone{generation: snapshot.generation, operation: "configs", text: string(data), err: err}
		}
	case "r":
		return m.loadSMBDirectory(b.share, b.directory)
	case "e":
		filename, err := exportSMBEntries(filepath.Join(m.appDir, "downloads"), b.host, b.share, b.directory, b.entries)
		if err != nil {
			m.message = err.Error()
		} else {
			m.message = "Список сохранён: " + filename
		}
	case "d":
		return m.downloadSelectedSMBFile()
	case "enter", "right":
		if b.index >= len(b.entries) {
			return m, nil
		}
		selected := b.entries[b.index]
		if b.share == "" {
			if strings.EqualFold(selected.Name, "IPC$") {
				m.message = "IPC$ — служебная шара RPC; файлового каталога здесь нет"
				return m, nil
			}
			return m.loadSMBDirectory(selected.Name, "")
		}
		remote := path.Join(b.directory, selected.Name)
		if selected.Directory {
			return m.loadSMBDirectory(b.share, remote)
		}
		m, ctx := m.beginSMBOperation()
		snapshot := m.smbBrowser
		return m, func() tea.Msg {
			defer snapshot.cancel()
			var data bytes.Buffer
			_, err := js.ReadSMBFileWithOptions(ctx, snapshot.options(), snapshot.share, remote, &data, 64*1024)
			return smbBrowserDone{generation: snapshot.generation, operation: "preview", directory: remote, text: smbPreview(data.Bytes(), selected.Size), err: err}
		}
	}
	return m, nil
}

func (m model) downloadSelectedSMBFile() (tea.Model, tea.Cmd) {
	b := m.smbBrowser
	if b.share == "" || b.index < 0 || b.index >= len(b.entries) || b.entries[b.index].Directory {
		m.message = "Выбери файл для скачивания"
		return m, nil
	}
	remote := path.Join(b.directory, b.entries[b.index].Name)
	m, ctx := m.beginSMBOperation()
	progress := &smbDownloadProgress{name: b.entries[b.index].Name, total: b.entries[b.index].Size, started: time.Now()}
	m.smbBrowser.download = progress
	snapshot := m.smbBrowser
	directory := filepath.Join(m.appDir, "downloads")
	return m, tea.Batch(tickSMBDownload(snapshot.generation), func() tea.Msg {
		defer snapshot.cancel()
		filename, err := js.DownloadSMBWithProgress(ctx, snapshot.options(), snapshot.share, remote, directory, progress.written.Store)
		return smbBrowserDone{generation: snapshot.generation, operation: "download", text: filename, err: err}
	})
}

func smbPreview(data []byte, size int64) string {
	text := ""
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		text = "Двоичный файл (hex):\n" + hex.Dump(data)
	} else {
		text = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) && r != '\n' && r != '\t' {
				return -1
			}
			return r
		}, string(data))
	}
	if text == "" {
		text = "(Пустой файл)"
	}
	if size > int64(len(data)) {
		text = fmt.Sprintf("Предпросмотр первых %d байт из %d\n\n", len(data), size) + text
	}
	return text
}

func exportSMBEntries(directory, host, share, remote string, entries []js.SMBEntry) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, "smb-list-*.csv")
	if err != nil {
		return "", err
	}
	writer := csv.NewWriter(file)
	err = writer.Write([]string{"host", "share", "path", "name", "directory", "size", "modified", "read", "write", "access_error"})
	for _, entry := range entries {
		if err != nil {
			break
		}
		modified := ""
		if !entry.Modified.IsZero() {
			modified = entry.Modified.Format("2006-01-02T15:04:05Z07:00")
		}
		err = writer.Write([]string{host, share, path.Join(remote, entry.Name), entry.Name, strconv.FormatBool(entry.Directory), strconv.FormatInt(entry.Size, 10), modified, smbPermissionCSV(entry.Read), smbPermissionCSV(entry.Write), entry.AccessError})
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

func (m model) viewInteractionMenu(w int) string {
	body := headingStyle.Render("Взаимодействие проекта") + fmt.Sprintf("\n\nХост: %s · h выбрать хост\n↑/↓ инструмент · Enter открыть\n\n", smbDisplayName(m.smbBrowser.host))
	rows := []string{
		fmt.Sprintf("SMB :%d — проводник шар (guest / без пароля)", m.smbBrowser.port),
		fmt.Sprintf("WinRM :%d — вход с учёткой, права, файлы, команды", m.winrmBrowser.options.Port),
		"MSSQL — учётка, аудит и интерактивная SQL-консоль",
		"Web LFI — проверка URL и параметра",
		fmt.Sprintf("FTP :%d — проводник (anonymous / учётка / FTPS)", m.ftpBrowser.options.Port),
		"PostgreSQL — учётка / без пароля, чтение таблиц и SQL",
		"MySQL / MariaDB — учётка / пустой пароль, чтение таблиц и SQL",
		"Web — поиск каталогов и файлов по словарю",
		"SSH — словарный перебор учёток",
		"Web SQLi — проверка форм на SQL-инъекции",
		"Web Upload — проверка загрузки PHP-файлов (RCE)",
		fmt.Sprintf("Kyocera :%d — выгрузка адресной книги без аутентификации", m.kyoceraBook.target.Port),
		"CVE — офлайн: сверить сохранённые версии (весь проект)",
		"NSE --script vuln — активные проверки (весь проект)",
	}
	lo, hi := windowRange(m.interactionIndex, len(rows), max(1, m.panelRows()-6))
	for i := lo; i < hi; i++ {
		body += renderListRow(rows[i], i == m.interactionIndex, w)
	}
	return m.renderPanel(w, body)
}

func (m model) viewSMBBrowser(w int) string {
	b := m.smbBrowser
	identity := b.mode + " / пустой пароль"
	if b.mode == "credential" {
		identity = "учётка " + smbDisplayName(credIdentLabel(b.credential))
	}
	body := headingStyle.Render("SMB — проводник") + fmt.Sprintf("\n%s:%d / %s / %s · %s\np — порт · a — null/guest · c — учётка · f — поиск конфигураций (чтение)\n", b.host, b.port, b.share, b.directory, identity)
	if len(b.entries) > 0 && b.entries[0].ListingTruncated {
		body += "Показаны первые 1000 записей; список ограничен\n"
	}
	if b.busy {
		if b.download != nil {
			p := b.download
			written := p.written.Load()
			percent := 0.0
			if p.total > 0 {
				percent = min(100.0, float64(written)*100/float64(p.total))
			}
			filled := int(percent / 5)
			speed := float64(written) / max(0.001, time.Since(p.started).Seconds())
			body += fmt.Sprintf("Скачивание: %s\n[%s%s] %.1f%% · %s / %s · %s/с · Esc — отменить\n", smbDisplayName(p.name), strings.Repeat("=", filled), strings.Repeat("-", 20-filled), percent, smbTransferSize(float64(written)), smbTransferSize(float64(p.total)), smbTransferSize(speed))
		} else {
			body += "Операция выполняется… Esc — отменить\n"
		}
	}
	if b.preview != "" {
		body += "\n" + smbDisplayName(b.previewTitle) + "\n"
		lines := strings.Split(ansi.Wrap(b.preview, max(1, w-6), ""), "\n")
		lo := min(b.offset, max(0, len(lines)-1))
		hi := min(len(lines), lo+max(1, m.panelRows()-1))
		body += strings.Join(lines[lo:hi], "\n")
	} else {
		if b.share == "" {
			body += "\nИмя шары                         Права доступа\n"
		} else {
			body += "\nИмя · размер · изменён\n"
		}
		lo, hi := windowRange(b.index, len(b.entries), max(1, m.panelRows()-1))
		if len(b.entries) == 0 && !b.busy {
			body += "Пусто. Если сервер отказал в доступе, причина указана внизу.\n"
		}
		for i := lo; i < hi; i++ {
			e := b.entries[i]
			name := smbDisplayName(e.Name)
			if e.Directory {
				name = "[DIR] " + name
			}
			details := ""
			if b.share != "" {
				details = fmt.Sprintf("  %d B  %s", e.Size, e.Modified.Format("02.01.2006 15:04"))
			}
			if b.share == "" {
				rights := smbRightsLabel(e)
				usable := max(1, w-8)
				nameWidth := max(1, usable-ansi.StringWidth(rights)-2)
				name = ansi.Truncate(name, nameWidth, "…")
				name += strings.Repeat(" ", max(2, usable-ansi.StringWidth(name)-ansi.StringWidth(rights))) + rights
			}
			body += renderListRow(name+details, i == b.index, w)
		}
	}
	if b.preview == "" && b.share == "" && b.index < len(b.entries) && b.entries[b.index].AccessError != "" {
		body += "\n" + smbDisplayName(b.entries[b.index].AccessError)
	}
	return m.renderPanel(w, body)
}

func smbDisplayName(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func smbPermissionCSV(permission *bool) string {
	if permission == nil {
		return ""
	}
	return strconv.FormatBool(*permission)
}

func smbRightsLabel(entry js.SMBEntry) string {
	if strings.EqualFold(entry.Name, "IPC$") {
		return "RPC (служебная)"
	}
	var permissions []string
	if entry.Read != nil && *entry.Read {
		permissions = append(permissions, "READ")
	}
	if entry.Write != nil && *entry.Write {
		permissions = append(permissions, "WRITE")
	}
	if entry.Read == nil {
		permissions = append(permissions, "READ ?")
	}
	if entry.Write == nil {
		permissions = append(permissions, "WRITE ?")
	}
	if len(permissions) == 0 {
		return "нет доступа"
	}
	return strings.Join(permissions, ", ")
}

func smbTransferSize(n float64) string {
	units := []string{"Б", "КиБ", "МиБ", "ГиБ", "ТиБ"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}
