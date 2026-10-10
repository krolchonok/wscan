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
		}
	}
	var names []string
	for name := range total {
		names = append(names, name)
	}
	sort.Strings(names)
	body := fmt.Sprintf("# Проверка библиотеки\n\nПроверено: %d. Nuclei загружаются: %d. NSE загружаются: %d.\n\n", len(entries), nuclei, nse)
	body += "Цели не сканировались. При наличии полных движков Nuclei проверен через -tl, NSE — через Nmap --script-help с библиотекой nselib. Без них используется ограниченный встроенный парсер. Это проверка загрузки, не выполнение проверок на цели; аргументы, доступы и зависимости могут потребоваться при запуске. Workflows и служебные YAML не являются отдельными исполняемыми проверками и не входят в каталог.\n\n| Сервис | Доступно | Всего |\n|---|---:|---:|\n"
	for _, name := range names {
		body += fmt.Sprintf("| %s | %d | %d |\n", name, available[name], total[name])
	}
	body += "\nПричины недоступности каждого шаблона: compatibility.json.\n"
	if err = os.WriteFile(filepath.Join(output, "README.md"), []byte(body), 0600); err != nil {
		return err
	}
	fmt.Printf("Проверено %d: Nuclei %d загружаются, NSE %d загружаются. Отчёт: %s\n", len(entries), nuclei, nse, output)
	return nil
}
