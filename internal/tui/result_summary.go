package tui

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"wscan/internal/domain"
	"wscan/internal/nse"
)

func resultClass(f domain.Finding) string {
	f.Severity = domain.EffectiveSeverity(f)
	if f.Severity == "error" || strings.HasPrefix(f.TemplateID, "nmap/") && nse.OutputIsError(f.Evidence) {
		return "Ошибка"
	}
	if strings.HasPrefix(f.TemplateID, "nmap/") && nse.OutputSeverity(f.Evidence) == "unknown" {
		return "Риск"
	}
	if f.Severity == "info" || f.Severity == "" {
		return "Сведения"
	}
	return "Риск"
}

func resultCounts(fs []domain.Finding, taskErrors ...int) string {
	counts := map[string]int{}
	for _, f := range fs {
		counts[resultClass(f)]++
	}
	if len(taskErrors) > 0 {
		counts["Ошибка"] = max(counts["Ошибка"], taskErrors[0])
	}
	return fmt.Sprintf("Риски: %d · Сведения: %d · Ошибки: %d", counts["Риск"], counts["Сведения"], counts["Ошибка"])
}

func (m model) serviceResultErrors(host string, service domain.Service) int {
	for i := len(m.jobs) - 1; i >= 0; i-- {
		j := m.jobs[i]
		if j.projectID != m.current.ID || !j.runsServiceChecks() {
			continue
		}
		if j.service != nil && (j.service.Host != service.Host || j.service.Port != service.Port || j.service.Protocol != service.Protocol) {
			continue
		}
		matched := false
		for _, target := range j.targets {
			if target == host {
				matched = true
			}
		}
		if !matched {
			continue
		}
		if j.result != nil {
			return len(j.result.Errors)
		}
		return 0
	}
	return 0
}

func resultRank(f domain.Finding) int {
	switch resultClass(f) {
	case "Ошибка":
		return 5
	case "Сведения":
		return 6
	}
	switch domain.EffectiveSeverity(f) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func orderedResults(fs []domain.Finding) []domain.Finding {
	var out []domain.Finding
	indices := map[string]int{}
	for _, f := range fs {
		key := f.TemplateID + "\x00" + f.MatchedAt + "\x00" + f.MatcherName
		if index, ok := indices[key]; ok {
			if f.Time.After(out[index].Time) {
				out[index] = f
			}
		} else {
			indices[key] = len(out)
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return resultRank(out[i]) < resultRank(out[j]) })
	return out
}

func resultTitle(f domain.Finding) string {
	if f.TemplateID == "nmap/vnc-info" && domain.EffectiveSeverity(f) == "critical" {
		return "VNC: сервер предлагает доступ без авторизации"
	}
	id := strings.TrimPrefix(f.TemplateID, "nmap/")
	names := map[string]string{
		"smb-version-detect":   "SMB: согласованная версия соединения",
		"smb-protocols":        "SMB: поддерживаемые версии",
		"smb-enum":             "SMB: имя машины, ОС и подпись",
		"ntlm-info":            "SMB: данные NTLM",
		"smb-enum-domains":     "SMB: имя домена / рабочей группы",
		"smb-os-detect":        "SMB: определение ОС",
		"smb-os-discovery":     "SMB: сведения об ОС",
		"smb2-security-mode":   "SMB: обязательность подписи",
		"smb-security-mode":    "SMB: настройки безопасности",
		"smb2-capabilities":    "SMB: возможности протокола",
		"smb2-server-time":     "SMB: время сервера",
		"smb2-time":            "SMB: время сервера",
		"smb-mbenum":           "SMB: перечисление браузеров сети",
		"smb-anonymous-access": "SMB: доступ без учётных данных",
		"smb-shares":           "SMB: доступные общие папки",
		"smb-signing":          "SMB: подпись не обязательна",
	}
	if title := names[id]; title != "" {
		return title
	}
	return f.Name
}

func resultLabel(f domain.Finding) string {
	class := resultClass(f)
	if class == "Сведения" {
		return resultTitle(f)
	}
	if class == "Риск" {
		class = map[string]string{"critical": "КРИТИЧЕСКИЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ", "low": "НИЗКИЙ"}[domain.EffectiveSeverity(f)]
		if class == "" {
			class = "РИСК"
		}
	}
	return "[" + class + "] " + resultTitle(f)
}

var smbDialectRE = regexp.MustCompile(`(?m)^\s*(2\.0\.2|2\.1|3\.0\.2|3\.0|3\.1\.1)\s*$`)

// Summaries use saved evidence, never template descriptions or guessed values.
func smbSummary(fs []domain.Finding) []string {
	latest := map[string]domain.Finding{}
	for _, f := range fs {
		if old, ok := latest[f.TemplateID]; !ok || f.Time.After(old.Time) {
			latest[f.TemplateID] = f
		}
	}
	fields := map[string]string{}
	if f, ok := latest["nmap/smb-protocols"]; ok {
		var versions []string
		for _, match := range smbDialectRE.FindAllStringSubmatch(f.Evidence, -1) {
			versions = append(versions, match[1])
		}
		if len(versions) > 0 {
			fields["Версии"] = strings.Join(uniqueStrings(versions), ", ")
		}
	}
	for _, id := range []string{"smb-version-detect", "smb-enum", "ntlm-info", "smb-enum-domains"} {
		f, ok := latest[id]
		if !ok {
			continue
		}
		var data struct {
			SupportV1           *bool
			SigningRequired     *bool
			OSVersion           string
			NetBIOSComputerName string
			NetBIOSDomainName   string
			Version             struct{ VerString string }
		}
		if json.Unmarshal([]byte(f.Response), &data) != nil {
			continue
		}
		if data.SupportV1 != nil {
			fields["SMBv1"] = map[bool]string{true: "поддерживается", false: "не обнаружен"}[*data.SupportV1]
		}
		if data.SigningRequired != nil {
			fields["Подпись"] = map[bool]string{true: "обязательна", false: "не обязательна"}[*data.SigningRequired]
		}
		if data.OSVersion != "" {
			fields["ОС сообщает"] = data.OSVersion
		}
		if data.NetBIOSComputerName != "" {
			fields["Машина"] = data.NetBIOSComputerName
		}
		if data.NetBIOSDomainName != "" {
			fields["Домен/группа"] = data.NetBIOSDomainName
		}
		if data.Version.VerString != "" {
			fields["Соединение"] = data.Version.VerString
		}
	}
	if f, ok := latest["nmap/smb2-security-mode"]; ok {
		if strings.Contains(f.Evidence, "signing enabled and required") {
			fields["Подпись"] = "обязательна (Nmap)"
		}
		if strings.Contains(f.Evidence, "signing enabled but not required") {
			fields["Подпись"] = "не обязательна (Nmap)"
		}
	}
	var out []string
	for _, key := range []string{"Версии", "Соединение", "SMBv1", "Подпись", "Машина", "ОС сообщает", "Домен/группа"} {
		if value := fields[key]; value != "" {
			out = append(out, key+": "+value)
		}
	}
	return out
}

func resultExplanation(f domain.Finding) string {
	if f.TemplateID == "ui/coercion-summary" {
		return f.Description
	}
	if f.Protocol == "offline" && strings.HasPrefix(f.TemplateID, "offline/cve/") {
		return f.Description
	}
	if resultClass(f) == "Ошибка" {
		return "Проверка не завершилась успешно. Её вывод не подтверждает наличие уязвимости."
	}
	switch strings.TrimPrefix(f.TemplateID, "nmap/") {
	case "vnc-info":
		if domain.EffectiveSeverity(f) == "critical" {
			return "Сервер предлагает способ доступа VNC без авторизации. Это критический риск; скрипт проверяет согласование способов защиты, но не подтверждает получение рабочего стола или возможность управления. Ограничьте сетевой доступ и включите авторизацию VNC."
		}
		return "Определены версия VNC и способы защиты. Этот результат сам по себе не подтверждает доступ без авторизации."
	case "smb-version-detect":
		return "Это версия, согласованная данной проверкой. Полный список поддерживаемых версий смотрите в «SMB: поддерживаемые версии»."
	case "smb-enum", "ntlm-info", "smb-enum-domains", "smb-os-detect", "smb-os-discovery":
		return "Сервис раскрыл сведения о машине. Имя домена может совпадать с именем рабочей группы; версия ОС не показывает установленные обновления."
	case "smb2-capabilities":
		return "Возможности протокола зависят от согласованной версии. Этот результат не доказывает, что шифрование выключено для всех соединений."
	case "smb2-server-time", "smb2-time":
		return "Время получено из ответа сервера. Поле времени запуска может отсутствовать или быть некорректным; его нельзя считать надёжным временем работы."
	case "smb2-security-mode":
		return "Настройка подписи получена при согласовании SMB. Смотрите версию протокола в доказательствах."
	}
	if resultClass(f) == "Сведения" {
		return "Информационный результат проверки; сам по себе не является подтверждённой уязвимостью."
	}
	return "Сработала проверка риска. Для оценки смотрите точный адрес, доказательства и условия шаблона."
}
