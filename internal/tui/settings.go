package tui

import (
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
)

var settingLabels = []string{
	"Проверки: запросов/сек (RPS)",
	"Проверки: параллельность",
	"Таймаут, секунды",
	"Повторные попытки",
	"Поиск портов: проб/сек",
	"Поиск портов: параллельность",
	"Поиск TCP-портов",
	"Диапазон портов",
	"Пресет скорости проверок",
	"Пресет скорости поиска портов",
	"Профиль запуска (скорость целиком)",
	"code: внешний интерпретатор (ruby/python/...)",
	"Ручной запуск интенсивных и exploit-проверок",
	"Защита от лок-аута: макс. неудачных попыток",
	"Защита от лок-аута: окно, минут",
	"Credential-атаки (spray / post-auth модули)",
}

const (
	settingLockoutMaxAttempts = 13
	settingLockoutWindow      = 14
	settingAllowCredAttack    = 15
)

func (m model) settingValues() []int {
	p := m.current
	return []int{p.RPS, p.Concurrency, p.TimeoutSeconds, p.Retries, p.DiscoveryRPS, p.DiscoveryConcurrency}
}

func (m model) settingRows() []string {
	rows := make([]string, len(settingLabels))
	for i, value := range m.settingValues() {
		rows[i] = fmt.Sprintf("%s: %d", settingLabels[i], value)
	}
	rows[6] = settingLabels[6] + ": " + map[bool]string{true: "включён", false: "выключен"}[m.current.DiscoveryEnabled]
	rows[7] = settingLabels[7] + ": " + map[bool]string{true: "1–65535", false: "основные порты"}[m.current.AllPorts]
	rows[8] = settingLabels[8] + ": " + speedName(m.current)
	rows[9] = settingLabels[9] + ": " + portSpeedName(m.current)
	rows[10] = settingLabels[10] + ": " + profileName(m.current)
	rows[11] = settingLabels[11] + ": " + map[bool]string{true: "включён (риск!)", false: "выключен"}[m.current.AllowCodeExec]
	rows[12] = settingLabels[12] + ": " + map[bool]string{true: "включён (риск!)", false: "выключен"}[m.current.AllowExploit]
	rows[settingLockoutMaxAttempts] = settingLabels[settingLockoutMaxAttempts] + ": " + lockoutValueDisplay(m.current.LockoutMaxAttempts, domain.DefaultLockoutMaxAttempts)
	rows[settingLockoutWindow] = settingLabels[settingLockoutWindow] + ": " + lockoutValueDisplay(m.current.LockoutWindowMinutes, domain.DefaultLockoutWindowMinutes)
	rows[settingAllowCredAttack] = settingLabels[settingAllowCredAttack] + ": " + map[bool]string{true: "включён (риск!)", false: "выключен"}[m.current.AllowCredentialAttack]
	return rows
}

// lockoutValueDisplay shows "0 (по умолчанию N)" for an unset (<=0) lockout
// setting — 0 means "use the conservative default", not "unlimited" (see
// domain.Project.LockoutMaxAttempts' doc comment), and the settings screen
// must not look like 0 silently disables the protection.
func lockoutValueDisplay(value, fallback int) string {
	if value <= 0 {
		return fmt.Sprintf("0 (по умолчанию %d)", fallback)
	}
	return fmt.Sprintf("%d", value)
}

func (m model) updateSettings(key string) (tea.Model, tea.Cmd) {
	p := m.current
	switch key {
	case "left", "right":
		switch m.settingsIndex {
		case 6:
			p.DiscoveryEnabled = !p.DiscoveryEnabled
		case 7:
			p.AllPorts = !p.AllPorts
		case 8, 9:
			p = cycleSpeed(p, m.settingsIndex == 9, key)
		case 10:
			p = cycleProfile(p, key)
		case 11:
			return m.toggleAllowCodeExec()
		case 12:
			return m.toggleAllowExploit()
		case settingAllowCredAttack:
			return m.toggleAllowCredentialAttack()
		default:
			return m, nil
		}
		return m.persistSettings(p)
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		m.settingsIndex = max(0, m.settingsIndex-1)
	case "down", "j":
		m.settingsIndex = min(len(settingLabels)-1, m.settingsIndex+1)
	case "enter", " ":
		if m.settingsIndex == 10 {
			p = cycleProfile(p, "right")
			return m.persistSettings(p)
		}
		if m.settingsIndex == 9 {
			m.openSpeedPresets()
			return m, nil
		}
		if m.settingsIndex == 8 {
			m.openSpeedPresets()
			return m, nil
		}
		if m.settingsIndex == 11 {
			return m.toggleAllowCodeExec()
		}
		if m.settingsIndex == 12 {
			return m.toggleAllowExploit()
		}
		if m.settingsIndex == settingAllowCredAttack {
			return m.toggleAllowCredentialAttack()
		}
		if m.settingsIndex < 6 {
			m.startInput("setting-value")
			m.input = strconv.Itoa(m.settingValues()[m.settingsIndex])
			return m, nil
		}
		if m.settingsIndex == settingLockoutMaxAttempts {
			m.startInput("setting-value")
			m.input = strconv.Itoa(m.current.LockoutMaxAttempts)
			return m, nil
		}
		if m.settingsIndex == settingLockoutWindow {
			m.startInput("setting-value")
			m.input = strconv.Itoa(m.current.LockoutWindowMinutes)
			return m, nil
		}
		if m.settingsIndex == 6 {
			p.DiscoveryEnabled = !p.DiscoveryEnabled
		} else {
			p.AllPorts = !p.AllPorts
		}
		return m.persistSettings(p)
	case "d":
		p.DiscoveryEnabled = !p.DiscoveryEnabled
		return m.persistSettings(p)
	case "a":
		p.AllPorts = !p.AllPorts
		return m.persistSettings(p)
	}
	return m, nil
}

func (m model) saveSettingValue(value string) (tea.Model, tea.Cmd) {
	m.screen = "settings"
	n, err := strconv.Atoi(value)
	minimum := 1
	if m.settingsIndex == 3 || m.settingsIndex == 0 || m.settingsIndex == 4 ||
		m.settingsIndex == settingLockoutMaxAttempts || m.settingsIndex == settingLockoutWindow {
		// 0 is valid here: it means "use the conservative default", not
		// "unlimited" — see lockoutValueDisplay and
		// domain.Project.LockoutMaxAttempts' doc comment.
		minimum = 0
	}
	if m.settingsIndex == 5 && n > 2048 {
		m.message = "Параллельность поиска портов: 1–2048."
		return m, nil
	}
	if err != nil || n < minimum {
		m.message = fmt.Sprintf("Введи целое число от %d.", minimum)
		return m, nil
	}
	p := m.current
	switch m.settingsIndex {
	case 0:
		p.RPS = n
	case 1:
		p.Concurrency = n
	case 2:
		p.TimeoutSeconds = n
	case 3:
		p.Retries = n
	case 4:
		p.DiscoveryRPS = n
	case 5:
		p.DiscoveryConcurrency = n
	case settingLockoutMaxAttempts:
		p.LockoutMaxAttempts = n
	case settingLockoutWindow:
		p.LockoutWindowMinutes = n
	}
	return m.persistSettings(p)
}

// toggleAllowCodeExec flips the project's code: execution opt-in. Turning it
// off needs no confirmation (always safe); turning it on routes through a
// dedicated warning screen first — code: shells out to a real external
// interpreter on the scanner's own machine, the one request type that steps
// outside the native engine, so it must never be a silent one-keystroke
// toggle (internal/engine/code.go has the full reasoning).
func (m model) toggleAllowCodeExec() (tea.Model, tea.Cmd) {
	if m.current.AllowCodeExec {
		p := m.current
		p.AllowCodeExec = false
		return m.persistSettings(p)
	}
	m.screen = "code-exec-confirm"
	return m, nil
}

// updateCodeExecConfirm handles the one-time warning shown before
// AllowCodeExec can become true for a project. Esc/n cancels back to
// settings with nothing changed; Enter/y acknowledges and enables it.
func (m model) updateCodeExecConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n":
		m.screen = "settings"
		return m, nil
	case "enter", "y":
		p := m.current
		p.AllowCodeExec = true
		m.screen = "settings"
		return m.persistSettings(p)
	}
	return m, nil
}

func (m model) viewCodeExecConfirm(w int) string {
	detail := "code:-шаблон запускает свой скрипт через реальный внешний интерпретатор " +
		"(ruby/python/bash/...) прямо на этой машине — не в песочнице, с правами процесса wscan.\n\n" +
		"Это единственный тип проверки, который выходит за пределы нашего нативного движка.\n" +
		"Включай только для доверенных шаблонов."
	return m.renderPanel(w, headingStyle.Render("Разрешить code: внешний интерпретатор?")+"\n\n"+detail+"\n\nEnter — разрешить для проекта «"+m.current.Name+"» · Esc — отмена")
}

// toggleAllowExploit flips the project's exploit: opt-in. Turning it off
// needs no confirmation (always safe); turning it on routes through a
// dedicated warning screen first — exploit: templates actually trigger the
// vulnerability against the target (command injection, auth bypass, path
// traversal, …), not just detect it, so it must never be a silent
// one-keystroke toggle (internal/engine/exec.go has the full reasoning).
func (m model) toggleAllowExploit() (tea.Model, tea.Cmd) {
	if m.current.AllowExploit {
		p := m.current
		p.AllowExploit = false
		return m.persistSettings(p)
	}
	m.screen = "exploit-confirm"
	return m, nil
}

// updateExploitConfirm handles the one-time warning shown before
// AllowExploit can become true for a project. Esc/n cancels back to
// settings with nothing changed; Enter/y acknowledges and enables it.
func (m model) updateExploitConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n":
		m.screen = "settings"
		return m, nil
	case "enter", "y":
		p := m.current
		p.AllowExploit = true
		m.screen = "settings"
		return m.persistSettings(p)
	}
	return m, nil
}

func (m model) viewExploitConfirm(w int) string {
	detail := "Интенсивные шаблоны могут выполнять brute force, fuzzing, загрузку файлов или " +
		"проверку, способную повлиять на стабильность сервиса. Exploit-шаблоны могут также " +
		"триггерить уязвимость.\n\n" +
		"Обычный check-only запуск пропускает такие шаблоны. Включай ручной режим только для " +
		"целей с явной авторизацией на активное тестирование."
	return m.renderPanel(w, headingStyle.Render("Разрешить интенсивные проверки?")+"\n\n"+detail+"\n\nEnter — разрешить для проекта «"+m.current.Name+"» · Esc — отмена")
}

// toggleAllowCredentialAttack flips the project's credential-attack opt-in
// (internal/engine.SprayCredentials/RunModule). Turning it off needs no
// confirmation; turning it on routes through a warning screen first — this
// gate controls real credentials being tried against real accounts, the
// same risk-weight warning pattern as AllowCodeExec/AllowExploit.
func (m model) toggleAllowCredentialAttack() (tea.Model, tea.Cmd) {
	if m.current.AllowCredentialAttack {
		p := m.current
		p.AllowCredentialAttack = false
		return m.persistSettings(p)
	}
	m.screen = "credential-attack-confirm"
	return m, nil
}

func (m model) updateCredentialAttackConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n":
		m.screen = "settings"
		return m, nil
	case "enter", "y":
		p := m.current
		p.AllowCredentialAttack = true
		m.screen = "settings"
		return m.persistSettings(p)
	}
	return m, nil
}

func (m model) viewCredentialAttackConfirm(w int) string {
	detail := "Включает проверку сохранённых credentials (пароль/NTLM-хеш) против реальных " +
		"сервисов (SSH/SMB/LDAP/WinRM/MySQL/MSSQL/Postgres/VNC) и post-auth модули поверх них.\n\n" +
		fmt.Sprintf("Встроенная защита от лок-аута (макс. %d неудачных попыток / %d минут по умолчанию, "+
			"настраивается выше) отключить нельзя — но сама попытка входа с неверным кредом всё равно "+
			"уходит на целевой сервис.\n\n", domain.DefaultLockoutMaxAttempts, domain.DefaultLockoutWindowMinutes) +
		"Включай только против целей и аккаунтов, на которые у тебя есть явная авторизация."
	return m.renderPanel(w, headingStyle.Render("Разрешить credential-атаки?")+"\n\n"+detail+"\n\nEnter — разрешить для проекта «"+m.current.Name+"» · Esc — отмена")
}

func (m model) persistSettings(p domain.Project) (tea.Model, tea.Cmd) {
	if err := m.store.SetProjectScanSettings(m.ctx, p); err != nil {
		m.message = "Не удалось сохранить настройки: " + err.Error()
		return m, nil
	}
	m.current = p
	for i := range m.projects {
		if m.projects[i].ID == p.ID {
			m.projects[i] = p
		}
	}
	m.message = "Сохранено для новых задач. Запущенные задачи сохраняют свои лимиты."
	return m, nil
}
