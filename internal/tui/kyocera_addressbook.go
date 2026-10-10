package tui

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type kyoceraState struct {
	target     domain.Service
	options    engine.KyoceraOptions
	busy       bool
	generation int
	cancel     context.CancelFunc
	output     string
}

type kyoceraDone struct {
	generation int
	result     *engine.KyoceraResult
	err        error
}

// serviceIsKyocera reports whether a discovered service looks like a Kyocera
// Net Viewer address-book endpoint worth offering the disclosure action for.
func serviceIsKyocera(s domain.Service) bool {
	if s.Port == 9091 {
		return true
	}
	hay := strings.ToLower(s.Name + " " + s.Product + " " + s.PortService)
	return strings.Contains(hay, "kyocera")
}

func (m model) openKyoceraSetup() (tea.Model, tea.Cmd) {
	b := &m.kyoceraBook
	if b.cancel != nil {
		b.cancel()
	}
	generation := b.generation + 1
	host := m.smbBrowser.host
	target := domain.Service{Host: host, Port: 9091, Protocol: "tcp", Name: "kyocera", Tunnel: "ssl"}
	for i, s := range m.servicesFor(m.currentHost()) {
		if serviceIsKyocera(s) {
			target = s
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	*b = kyoceraState{generation: generation, target: target, options: engine.KyoceraOptions{Number: 25, WaitSecs: 5, Insecure: true}}
	m.screen = "kyocera-book"
	m.message = ""
	return m, nil
}

func (m model) updateKyocera(key string) (tea.Model, tea.Cmd) {
	b := &m.kyoceraBook
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.busy = false
			m.message = "Запрос адресной книги отменён"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = "interaction-menu"
	case "p":
		m.startInput("kyocera-port")
		m.input = strconv.Itoa(b.target.Port)
	case "w":
		m.startInput("kyocera-wait")
		m.input = strconv.Itoa(b.options.WaitSecs)
	case "t":
		b.options.Insecure = !b.options.Insecure
	case "enter":
		return m.startKyocera()
	}
	return m, nil
}

func (m model) startKyocera() (tea.Model, tea.Cmd) {
	b := &m.kyoceraBook
	if !m.current.AllowExploit {
		m.message = "Выгрузка адресной книги Kyocera требует AllowExploit"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.generation++
	b.busy = true
	b.output = ""
	snapshot := *b
	store, project := m.store, m.current
	return m, func() tea.Msg {
		defer cancel()
		result, err := engine.FetchKyoceraAddressBook(ctx, snapshot.target, snapshot.options)
		if err == nil && result != nil && len(result.Contacts) > 0 {
			runID, saveErr := store.StartRun(ctx, project.ID)
			if saveErr == nil {
				severity := "medium"
				if result.WithSecrets > 0 {
					severity = "high"
				}
				evidence := fmt.Sprintf("Выгружено записей: %d; с паролями FTP/SMB: %d; аутентификация не требовалась", len(result.Contacts), result.WithSecrets)
				saveErr = store.SaveFinding(ctx, runID, domain.Finding{
					TemplateID: "native/kyocera-address-book",
					Name:       "Kyocera: раскрытие адресной книги без аутентификации (CVE-2022-1026)",
					Severity:   severity,
					Target:     net.JoinHostPort(snapshot.target.Host, strconv.Itoa(snapshot.target.Port)),
					MatchedAt:  result.Endpoint,
					Evidence:   evidence,
					References: []string{"https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/"},
					Risk:       "exploit",
					Time:       time.Now().UTC(),
				})
				status := "completed"
				if saveErr != nil {
					status = "failed"
				}
				finishCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				finishErr := store.FinishRun(finishCtx, runID, status)
				stop()
				if saveErr == nil {
					saveErr = finishErr
				}
			}
			if saveErr != nil {
				err = fmt.Errorf("данные получены, но сохранение не завершено: %w", saveErr)
			}
		}
		return kyoceraDone{snapshot.generation, result, err}
	}
}

func (m model) applyKyoceraDone(done kyoceraDone) (tea.Model, tea.Cmd) {
	b := &m.kyoceraBook
	if done.generation != b.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.err != nil {
		m.message = "Kyocera: " + smbDisplayName(done.err.Error())
	}
	if done.result != nil {
		b.output = renderKyoceraResult(done.result)
	}
	return m, nil
}

func renderKyoceraResult(r *engine.KyoceraResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Endpoint: %s\nЗапросов: %d · записей: %d · с паролями: %d\n", smbDisplayName(r.Endpoint), r.Requests, len(r.Contacts), r.WithSecrets)
	if len(r.Contacts) == 0 {
		sb.WriteString("\nАдресная книга пуста либо структура ответа не распознана.")
		return sb.String()
	}
	for i, c := range r.Contacts {
		fmt.Fprintf(&sb, "\n[%d] %s", i+1, smbDisplayName(firstKyoceraLabel(c.Name, c.ID)))
		writeKyoceraLine(&sb, "Email", c.Email)
		writeKyoceraLine(&sb, "FTP", kyoceraTarget(c.FTPServer, c.FTPPort))
		writeKyoceraLine(&sb, "FTP логин", c.FTPLogin)
		writeKyoceraSecret(&sb, "FTP пароль", c.FTPPassword)
		writeKyoceraLine(&sb, "SMB", kyoceraTarget(c.SMBServer, c.SMBPort))
		writeKyoceraLine(&sb, "SMB логин", c.SMBLogin)
		writeKyoceraSecret(&sb, "SMB пароль", c.SMBPassword)
	}
	return sb.String()
}

func writeKyoceraLine(sb *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(sb, "\n    %s: %s", label, smbDisplayName(value))
}

func writeKyoceraSecret(sb *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(sb, "\n    %s: !! %s !!", label, smbDisplayName(value))
}

func kyoceraTarget(server, port string) string {
	if server == "" {
		return ""
	}
	if port == "" {
		return server
	}
	return server + ":" + port
}

func firstKyoceraLabel(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "(без имени)"
}

func (m model) viewKyocera(w int) string {
	b := m.kyoceraBook
	tls := "да"
	if b.options.Insecure {
		tls = "нет (самоподписанные сертификаты)"
	}
	body := headingStyle.Render("Kyocera — адресная книга (CVE-2022-1026)") + fmt.Sprintf(
		"\nСервис: %s:%d\nПроверка TLS: %s · пауза: %dс\n\np порт · w пауза · t проверка TLS · Enter получить\nБез аутентификации; возвращает email и пароли FTP/SMB из книги.\n\n%s",
		b.target.Host, b.target.Port, tls, b.options.WaitSecs, b.output)
	if b.busy {
		body += "\nВыполняется… Esc отменить"
	}
	return m.renderPanel(w, body)
}
