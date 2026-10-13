package tui

// Workspace navigation has one definition for the key router and the UI.
// Editors, confirmations and interactive consoles retain their own keys.
var workspaceTabs = []struct{ key, label, screen string }{
	{"0", "Разведка", "recon"},
	{"1", "Подсети", "networks"}, {"2", "Хосты", "desk"}, {"3", "Задачи", "jobs"}, {"4", "Взаимодействие", "interaction-menu"}, {"5", "Результаты", "project-results"},
}

func (m model) workspaceNavigationAllowed() bool {
	if m.current.ID <= 0 || m.resultDeleteConfirm {
		return false
	}
	switch m.screen {
	case "recon", "overview", "desk", "networks", "jobs", "job-details", "interaction-menu", "project-results", "finding-details", "history":
		return true
	case "service-inventory":
		return !m.serviceInventoryEditing
	}
	return false
}
func (m model) navigateWorkspace(key string) (model, bool) {
	if !m.workspaceNavigationAllowed() {
		return m, false
	}
	switch key {
	case "0":
		m.openHostScope("")
		m.screen, m.message = "recon", ""
	case "1":
		m.screen, m.message = "networks", ""
	case "2":
		m.openHostScope("")
		m.message = ""
	case "3":
		m.jobsReturn, m.screen = m.screen, "jobs"
	case "4":
		m.openProjectInteractions()
	case "5":
		m.openProjectResults()
	default:
		return m, false
	}
	return m, true
}
func workspaceSection(screen string) string {
	switch screen {
	case "job-details":
		return "jobs"
	case "finding-details", "history":
		return "project-results"
	case "service-inventory":
		return "desk"
	}
	return screen
}
func screenTitle(screen string) string {
	titles := map[string]string{
		"checks-menu": "Проверки", "ad-menu": "AD", "recon": "Разведка", "overview": "Обзор", "guided-scan": "Начать проверку", "projects": "Проекты", "desk": "Хосты", "networks": "Подсети", "jobs": "Задачи", "job-details": "Итог задачи", "history": "История запусков", "project-results": "Результаты", "finding-details": "Результаты",
		"interaction-menu": "Взаимодействие", "interaction-targets": "Выбор машины", "smb-setup": "Вход SMB", "smb-browser": "SMB-проводник", "ftp-setup": "Вход FTP", "ftp-browser": "FTP-проводник", "winrm-setup": "Вход WinRM", "winrm-browser": "WinRM-проводник", "winrm-shell": "Консоль WinRM",
		"pg-setup": "Вход PostgreSQL", "pg-console": "PostgreSQL", "mysql-setup": "Вход MySQL", "mysql-console": "MySQL", "mssql-setup": "Вход MSSQL", "mssql-console": "MSSQL", "mssql-actions": "Действия MSSQL", "mssql-xp-confirm": "Подтверждение команды MSSQL",
		"web-discovery": "Поиск Web", "web-wordlists": "Словари Web", "sqli-form": "Проверка SQLi", "file-upload": "Проверка загрузки файлов", "lfi-audit": "Проверка LFI", "ssh-dictionary": "Проверка SSH", "ssh-password-lists": "Словари SSH", "kyocera-book": "Адресная книга Kyocera",
		"coerce-setup": "Coerce / Responder", "ad-access": "Проверки доступа AD", "ad-scan": "Обнаружение AD", "coerce-port-check": "Проверка порта приёмника", "coerce-port-confirm": "Освобождение порта приёмника", "coerce-port-stopping": "Подготовка приёмника",
		"service-inventory": "Порты и службы", "host-selection": "Выбор хостов", "host-port-selection": "Выбор порта", "action-menu": "Действия", "disc-options": "Параметры обнаружения", "scan-review": "Перед запуском", "catalog": "Проверки", "catalog-groups": "Библиотека проверок",
		"global-settings": "Общие настройки", "settings": "Настройки проекта", "speed-presets": "Скорость проверки", "library-settings": "Библиотека", "dependency-settings": "Зависимости", "dependency-install-confirm": "Установка зависимости",
		"credentials": "Учётные записи", "cred-add-type": "Тип учётных данных", "cred-delete-confirm": "Удаление учётки", "project-delete-confirm": "Удаление проекта", "delete-confirm": "Удаление", "repair-target": "Исправление адреса", "input": "Ввод", "help": "Клавиши",
		"code-exec-confirm": "Запуск кода", "exploit-confirm": "Активные проверки", "credential-attack-confirm": "Проверки учётных данных", "spray-setup": "Проверка учёток", "spray-running": "Проверка учёток", "spray-results": "Результаты входа", "spray-module-picker": "Действия после входа", "spray-module-result": "Результат действия",
	}
	if title := titles[screen]; title != "" {
		return title
	}
	return "Экран приложения"
}
