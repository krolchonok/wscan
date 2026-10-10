package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Audit writes every catalog entry and its compatibility result without opening
// a project database or making requests to any target.
func (c *Catalog) Audit(output string) error {
	c.dir = output
	if c.libraryDir == "" {
		return fmt.Errorf("локальная library не найдена")
	}
	entries, err := c.List()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "compatibility.json"), data, 0600); err != nil {
		return err
	}
	total, available := map[string]int{}, map[string]int{}
	nuclei, nse := 0, 0
	reasons := map[string]int{}
	for _, e := range entries {
		d := Direction(e)
		total[d]++
		if e.Available {
			available[d]++
			if strings.HasPrefix(e.Path, "nmap/") {
				nse++
			} else {
				nuclei++
			}
		} else {
			reason := e.Reason
			if reason == "" {
				reason = e.NetworkReason
			}
			if reason == "" {
				reason = "not compatible"
			}
			reasons[reason]++
		}
	}
	summary := struct {
		Mode                     string         `json:"mode"`
		Total                    int            `json:"total"`
		NativeCompatible         int            `json:"native_compatible"`
		Unavailable              int            `json:"unavailable"`
		YAMLCompatible           int            `json:"yaml_compatible"`
		NSECompatible            int            `json:"nse_compatible"`
		TargetExecutionsVerified int            `json:"target_executions_verified"`
		Reasons                  map[string]int `json:"unavailable_reasons"`
	}{"native-offline", len(entries), nuclei + nse, len(entries) - nuclei - nse, nuclei, nse, 0, reasons}
	data, err = json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "summary.json"), data, 0600); err != nil {
		return err
	}
	var names []string
	for name := range total {
		names = append(names, name)
	}
	sort.Strings(names)
	body := fmt.Sprintf("# Совместимость библиотеки с нашим движком\n\nВсего проверок: %d. YAML совместимы: %d. NSE совместимы офлайн: %d. Недоступно: %d.\n\n", len(entries), nuclei, nse, len(entries)-nuclei-nse)
	body += "Это офлайн-проверка парсинга, поддержанных возможностей и импорта NSE. Внешние Nuclei, Nmap и Metasploit не запускались. Проверок на целях выполнено: **0**. Совместимость не подтверждает выполнение каждого API, наличие доступа, выполнение pre-condition или обнаружение уязвимости. code: требует интерпретатор и отдельное разрешение проекта. Workflows и служебные YAML не входят в каталог отдельных проверок.\n\n| Сервис | Совместимо офлайн | Всего |\n|---|---:|---:|\n"
	for _, name := range names {
		body += fmt.Sprintf("| %s | %d | %d |\n", name, available[name], total[name])
	}
	body += "\nОбщие числа и причины: summary.json. Причины недоступности каждого шаблона: compatibility.json.\n"
	if err = os.WriteFile(filepath.Join(output, "README.md"), []byte(body), 0600); err != nil {
		return err
	}
	fmt.Printf("Офлайн проверено %d: YAML совместимы %d, NSE совместимы офлайн %d; на целях выполнено 0. Отчёт: %s\n", len(entries), nuclei, nse, output)
	return nil
}
