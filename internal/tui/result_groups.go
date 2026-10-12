package tui

import (
	"fmt"
	"net"
	"strings"
	"wscan/internal/domain"
)

func coercionResult(f domain.Finding) bool {
	return strings.HasPrefix(f.TemplateID, "ad-access/coercion/") || strings.HasPrefix(f.TemplateID, "ad-access/responder/")
}
func groupedProjectResults(fs []domain.Finding) []domain.Finding {
	var out []domain.Finding
	groups := map[string][]domain.Finding{}
	var hosts []string
	for _, f := range fs {
		if !coercionResult(f) {
			out = append(out, f)
			continue
		}
		if _, ok := groups[f.Target]; !ok {
			hosts = append(hosts, f.Target)
		}
		groups[f.Target] = append(groups[f.Target], f)
	}
	for _, host := range hosts {
		out = append(out, coercionSummary(host, groups[host]))
	}
	return orderedResults(out)
}
func coercionSummary(host string, fs []domain.Finding) domain.Finding {
	f := domain.Finding{Target: host, MatchedAt: "ad://" + net.JoinHostPort(host, "445") + "/coercion-summary", TemplateID: "ui/coercion-summary", Protocol: "ad", Severity: "info"}
	// A saved report timestamps SMB first; keep conclusions from the newest
	// report rather than combining a past success with a newer failed attempt.
	var baseline domain.Finding
	for _, v := range fs {
		if v.Time.After(f.Time) {
			f.Time = v.Time
		}
		if v.TemplateID == "ad-access/coercion/smb" && v.Time.After(baseline.Time) {
			baseline = v
		}
	}
	stages := map[string]bool{}
	var methods []string
	denied, unavailable, discovery := 0, 0, 0
	for _, v := range fs {
		if !baseline.Time.IsZero() && v.Time.Before(baseline.Time) {
			continue
		}
		id := v.TemplateID
		stage := id[strings.LastIndex(id, "/")+1:]
		stages[stage] = true
		if strings.Contains(id, "/callback/") || strings.Contains(id, "/responder/") {
			continue
		}
		if stage == "smb" {
			continue
		}
		switch v.MatcherName {
		case "denied":
			denied++
		case "unavailable":
			unavailable++
		}
		if strings.Contains(v.Evidence, "RPC bind выполнен") {
			if strings.Contains(v.Evidence, "вызов отправлен") {
				methods = append(methods, stage)
			} else {
				discovery++
			}
		}
	}
	switch {
	case stages["skipped-local"]:
		f.Name = "Coerce: локальный приёмник исключён из целей"
		f.MatcherName = "skipped"
		f.Description = "Эта машина использовалась как приёмник и не проверялась как цель Coerce."
	case stages["ntlm-authenticate"]:
		f.Name = "Coerce: получен непустой NTLM-ответ"
		f.Severity = "high"
		f.MatcherName = "response"
		f.Description = "Машина подключилась к приёмнику и прислала непустой ответ NTLM. Подлинность ответа не проверена; получение доступа не подтверждено."
	case stages["anonymous-authenticate"]:
		f.Name = "Coerce: подключение есть, учётные данные не переданы"
		f.MatcherName = "anonymous"
		f.Description = "Машина подключилась к приёмнику, но прислала анонимный Authenticate без учётных данных."
	case stages["ntlm-negotiate"]:
		f.Name = "Coerce: NTLM начат, обмен не завершён"
		f.MatcherName = "incomplete"
		f.Description = "Обратное SMB-соединение наблюдалось. Клиент начал NTLM, но непустой Authenticate не получен."
	case stages["connection"] || stages["smb-negotiated"]:
		f.Name = "Coerce: обратное соединение получено"
		f.MatcherName = "callback"
		f.Description = "Машина подключилась к приёмнику. Передача учётных данных не подтверждена."
	case denied > 0 && len(methods) == 0 && discovery == 0:
		f.Name = "Coerce: отказ в доступе, проверка не выполнена"
		f.MatcherName = "denied"
		f.Severity = "error"
		f.Description = "SMB/RPC отказал во входе. Проверь выбранную учётку. По этому результату уязвимость оценить нельзя."
	case discovery > 0:
		f.Name = "Coerce: RPC доступен, принуждение не проверялось"
		f.MatcherName = "discovery"
		f.Description = "Выполнена проверка RPC bind. Она не подтверждает возможность обратного соединения."
	case baseline.MatcherName == "incomplete" || baseline.MatcherName == "error":
		f.Name = "Coerce: SMB-соединение не установлено"
		f.MatcherName = "incomplete"
		f.Severity = "error"
		f.Description = "Машина не ответила на подключение к TCP/445; Coerce не проверен."
	default:
		f.Name = "Coerce: обратное соединение не подтверждено"
		f.MatcherName = "incomplete"
		f.Description = "Обратное соединение не наблюдалось. Это не доказывает защищённость машины."
	}
	f.Evidence = f.Description
	if len(methods) > 0 {
		f.Evidence += "\nRPC-вызовы отправлены: " + strings.Join(uniqueStrings(methods), ", ")
	}
	if unavailable > 0 {
		f.Evidence += fmt.Sprintf("\nНедоступных RPC-методов: %d", unavailable)
	}
	var raw strings.Builder
	for _, v := range fs {
		fmt.Fprintf(&raw, "%s · %s · %s\n%s\n\n", v.Time.Local().Format("02.01 15:04:05"), v.TemplateID, v.MatcherName, v.Evidence)
	}
	f.Response = raw.String()
	return f
}
