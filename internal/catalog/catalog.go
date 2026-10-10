package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"wscan/internal/libsync"
	"wscan/internal/nse"
	tpl "wscan/internal/template"
)

const treeURL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
const rawBase = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"

type Entry struct {
	NetworkReason string `json:"network_reason,omitempty"`
	TemplateID    string `json:"template_id,omitempty"`
	GlobalScope   bool   `json:"global_scope,omitempty"`
	Impact        string `json:"impact,omitempty"`
	Service       string `json:"service,omitempty"` // from library/categories.json when present
	Path          string `json:"path"`
	SHA           string `json:"sha"`
	Size          int64  `json:"size"`
	Category      string `json:"category,omitempty"`
	Type          string `json:"type,omitempty"`
	Product       string `json:"product,omitempty"`
	SearchText    string `json:"search_text,omitempty"`
	Checked       bool   `json:"checked,omitempty"`
	Available     bool   `json:"available,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

var nseCategoriesRE = regexp.MustCompile(`(?s)categories\s*=\s*\{([^}]*)\}`)
var nseCategoryRE = regexp.MustCompile(`[\"']([^\"']+)[\"']`)
var nucleiNameRE = regexp.MustCompile(`(?m)^\s*name:\s*([^\r\n]+)`)
var nucleiTagsRE = regexp.MustCompile(`(?m)^\s*tags:\s*[\"']?([^\r\n\"']+)`)
var nucleiIDRE = regexp.MustCompile(`(?m)^id:\s*([^\r\n]+)`)
var yearRE = regexp.MustCompile(`^\d{4}$`)

type tree struct {
	Tree      []Entry `json:"tree"`
	Truncated bool    `json:"truncated"`
}
type Catalog struct {
	metadataMu        sync.RWMutex
	metadataPaths     map[string]string
	dir               string
	libraryDir        string
	client            *http.Client
	categoriesMu      sync.Mutex
	categoriesLoaded  bool
	categoriesPresent bool
	categoriesError   error
	categories        map[string]categoryEntry
}

func New(dir string) *Catalog {
	return &Catalog{dir: dir, client: &http.Client{Timeout: 45 * time.Second}}
}
func NewWithLibrary(dir, libraryDir string) *Catalog {
	c := New(dir)
	c.libraryDir = libraryDir
	return c
}
func (c *Catalog) LibraryDir() string { return c.libraryDir }
func (c *Catalog) Sync(ctx context.Context) ([]Entry, error) {
	if c.libraryDir != "" {
		return c.List()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, treeURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wscan-template-catalog")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub catalog returned %s", resp.Status)
	}
	var t tree
	if err = json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	if t.Truncated {
		return nil, fmt.Errorf("GitHub tree was truncated; catalog was not replaced")
	}
	entries := make([]Entry, 0, len(t.Tree))
	for _, e := range t.Tree {
		if strings.HasSuffix(e.Path, ".yaml") || strings.HasSuffix(e.Path, ".yml") {
			if tpl.LocalTemplateReason(nil, e.Path) != "" {
				continue
			}
			entries = append(entries, e)
		}
	}
	if err = os.MkdirAll(c.dir, 0700); err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(entries, "", "  ")
	if err = os.WriteFile(filepath.Join(c.dir, "catalog.json"), b, 0600); err != nil {
		return nil, err
	}
	return entries, nil
}
func (c *Catalog) List() ([]Entry, error) {
	if err := c.categoryIndexError(); err != nil {
		return nil, err
	}
	entries := make(map[string]Entry)
	var err error
	if c.libraryDir == "" {
		b, readErr := os.ReadFile(filepath.Join(c.dir, "catalog.json"))
		if readErr == nil {
			var remote []Entry
			if err = json.Unmarshal(b, &remote); err != nil {
				return nil, err
			}
			for _, entry := range remote {
				if tpl.LocalTemplateReason(nil, entry.Path) != "" {
					continue
				}
				entries[entry.Path] = entry
			}
		} else {
			err = readErr
		}
	}
	if c.libraryDir != "" {
		for _, root := range []struct{ dir, prefix, suffix string }{
			{libsync.TemplateDir(c.libraryDir), "", ".yaml"},
			{libsync.TemplateDir(c.libraryDir), "", ".yml"},
			{filepath.Join(c.libraryDir, "nmap", "scripts"), "nmap/scripts/", ".nse"},
		} {
			walkErr := filepath.WalkDir(root.dir, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.IsDir() {
					if path != root.dir && strings.HasPrefix(d.Name(), ".") {
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(strings.ToLower(d.Name()), root.suffix) {
					return nil
				}
				rel, err := filepath.Rel(root.dir, path)
				if err != nil {
					return err
				}
				var content []byte
				if root.prefix == "" {
					// Ignore repository metadata YAML; actual templates and workflows have a root id.
					b, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					content = b
					if strings.HasPrefix(filepath.ToSlash(rel), "workflows/") {
						return nil
					}
					if !hasNucleiDocument(content) {
						return nil
					}
				}
				name := root.prefix + filepath.ToSlash(rel)
				if !c.scopeAllows(name) {
					return nil
				}
				category := "Без категории"
				templateType := "Прочее"
				product := "Не определён"
				searchText := ""
				if root.prefix != "" {
					b, readErr := os.ReadFile(path)
					if readErr != nil {
						return readErr
					}
					content = b
					var values []string
					if match := nseCategoriesRE.FindSubmatch(b); len(match) == 2 {
						for _, value := range nseCategoryRE.FindAllSubmatch(match[1], -1) {
							values = append(values, string(value[1]))
						}
					}
					if len(values) > 0 {
						category = strings.Join(values, ", ")
					}
					templateType = nseTypeNames(values)
					product = nseProduct(filepath.Base(rel))
					searchText = category + " " + templateType + " " + product
				} else {
					nameMatch := nucleiNameRE.FindSubmatch(content)
					tagsMatch := nucleiTagsRE.FindSubmatch(content)
					var templateName, tags string
					if len(nameMatch) == 2 {
						templateName = strings.Trim(strings.TrimSpace(string(nameMatch[1])), "\"'")
					}
					if len(tagsMatch) == 2 {
						tags = strings.TrimSpace(string(tagsMatch[1]))
					}
					searchText = templateName + " " + tags
					templateType = nucleiType(filepath.ToSlash(rel))
					product = nucleiProduct(filepath.ToSlash(rel), tags)
					category = templateType
				}
				if root.prefix == "" && tpl.LocalTemplateReason(content, name) != "" {
					return nil
				}
				if _, exists := entries[name]; !exists {
					entry := Entry{Path: name, Size: int64(len(content)), Category: category, Type: templateType, Product: product, SearchText: searchText}
					entry.SHA = fmt.Sprintf("%x", sha256.Sum256(content))
					entry.Impact = classifyImpact(entry, content)
					if cat, ok := c.categoryFor(name); ok {
						applyCategory(&entry, cat)
					}
					entry.GlobalScope = root.prefix != "" && !nse.HasServiceRule(content)
					if root.prefix == "" {
						entry.NetworkReason = tpl.NetworkTemplateReason(content)
					}
					if root.prefix != "" {
						entry.TemplateID = "nmap/" + strings.TrimSuffix(filepath.Base(name), ".nse")
					} else if match := nucleiIDRE.FindSubmatch(content); len(match) == 2 {
						entry.TemplateID = strings.Trim(strings.TrimSpace(string(match[1])), "\"'")
					}
					// Availability reflects our own native engine only: a template
					// is "available" when the native parser/NSE loader can run it.
					entry.Checked = true
					entry.Available, entry.Reason = CheckWithLibrary(content, name, c.libraryDir)
					entries[name] = entry
				}
				return nil
			})
			if walkErr != nil && !os.IsNotExist(walkErr) {
				return nil, walkErr
			}
		}
	}
	if len(entries) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("template library is empty")
	}
	e := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		e = append(e, entry)
	}
	sort.Slice(e, func(i, j int) bool { return e[i].Path < e[j].Path })
	paths := map[string]string{}
	for _, entry := range e {
		if entry.TemplateID != "" {
			paths[entry.TemplateID] = entry.Path
		}
	}
	c.metadataMu.Lock()
	c.metadataPaths = paths
	c.metadataMu.Unlock()
	for i := range e {
		if e[i].NetworkReason != "" {
			e[i].Checked, e[i].Available, e[i].Reason = true, false, e[i].NetworkReason
		}
		if e[i].GlobalScope {
			e[i].Checked = true
			e[i].Available = false
			e[i].Reason = "Скрипт prerule/postrule выполняется вне выбранного хоста/порта"
		}
	}
	return e, nil
}
func (c *Catalog) Load(ctx context.Context, path string) ([]byte, error) {
	if err := c.categoryIndexError(); err != nil {
		return nil, err
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if strings.HasPrefix(clean, "../") || filepath.IsAbs(path) {
		return nil, fmt.Errorf("invalid template path")
	}
	if reason := tpl.LocalTemplateReason(nil, clean); reason != "" {
		return nil, fmt.Errorf("%s", reason)
	}
	if !c.scopeAllows(clean) {
		return nil, fmt.Errorf("проверка исключена из внешнего каталога: %s", clean)
	}
	if c.libraryDir != "" {
		base, rel := libsync.TemplateDir(c.libraryDir), clean
		if strings.HasPrefix(clean, "nmap/scripts/") {
			base, rel = filepath.Join(c.libraryDir, "nmap"), strings.TrimPrefix(clean, "nmap/")
		}
		local := filepath.Join(base, filepath.FromSlash(rel))
		if inside, err := filepath.Rel(base, local); err == nil && inside != ".." && !strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			if b, err := os.ReadFile(local); err == nil {
				return b, nil
			}
		}
		return nil, fmt.Errorf("шаблон отсутствует в скачанной библиотеке: %s", clean)
	}
	dest := filepath.Join(c.dir, "files", filepath.FromSlash(clean))
	var currentSHA string
	if entries, err := c.List(); err == nil {
		for _, entry := range entries {
			if entry.Path == clean {
				currentSHA = entry.SHA
				break
			}
		}
	}
	if b, err := os.ReadFile(dest); err == nil {
		cachedSHA, _ := os.ReadFile(dest + ".sha")
		if currentSHA == "" || strings.TrimSpace(string(cachedSHA)) == currentSHA {
			return b, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawBase+clean, nil)
	req.Header.Set("User-Agent", "wscan-template-catalog")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("template download returned %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(dest, b, 0600); err != nil {
		return nil, err
	}
	if currentSHA != "" {
		if err = os.WriteFile(dest+".sha", []byte(currentSHA), 0600); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func nucleiType(path string) string {
	path = strings.ToLower(path)
	if strings.Contains(path, "/credential-stuffing/") || strings.Contains(path, "wp-xmlrpc-brute-force") {
		return "Подбор учётных данных"
	}
	parts := strings.Split(path, "/")
	for _, part := range parts[1:] {
		if label := map[string]string{
			"cves": "Уязвимости · CVE", "cnvd": "Уязвимости · CNVD", "vulnerabilities": "Уязвимости",
			"misconfiguration": "Ошибки конфигурации", "misconfig": "Ошибки конфигурации",
			"exposures": "Экспозиции и утечки", "exposed-panels": "Панели управления",
			"default-logins": "Подбор учётных данных", "default-login": "Подбор учётных данных", "credential-stuffing": "Подбор учётных данных",
			"technologies": "Обнаружение технологий", "osint": "OSINT и разведка",
			"takeovers": "Захват поддоменов", "fuzz": "Fuzzing", "enumeration": "Перечисление",
			"detection": "Обнаружение сервисов", "jarm": "TLS/JARM отпечатки", "honeypot": "Обнаружение honeypot",
		}[part]; label != "" {
			return label
		}
	}
	if len(parts) == 0 {
		return "Прочее"
	}
	switch parts[0] {
	case "cloud":
		return "Облачные проверки"
	case "network":
		return "Сетевые проверки"
	case "file":
		return "Файлы и секреты"
	case "code":
		return "Проверки кода"
	case "javascript":
		return "JavaScript"
	case "dast":
		return "DAST"
	case "dns":
		return "DNS"
	case "ssl":
		return "TLS/SSL"
	case "headless":
		return "Браузерные проверки"
	default:
		return "HTTP · прочее"
	}
}

var nonProductTags = map[string]bool{
	"cve": true, "vuln": true, "vulnerability": true, "misconfig": true, "misconfiguration": true,
	"exposure": true, "exposed": true, "panel": true, "default-login": true, "default-credentials": true,
	"tech": true, "technology": true, "discovery": true, "detect": true, "enumeration": true, "enum": true,
	"cloud": true, "devops": true, "osint": true, "network": true, "http": true, "dns": true, "tcp": true, "udp": true,
	"intrusive": true, "safe": true, "dos": true, "fuzz": true, "brute": true, "bruteforce": true,
	"exploit": true, "rce": true, "sqli": true, "xss": true, "ssrf": true, "lfi": true, "rfi": true,
	"oast": true, "oob": true, "kev": true, "vkev": true, "unauth": true, "unauthenticated": true,
	"auth": true, "login": true, "file-upload": true, "token": true, "api": true, "wordpress-plugin": true,
}

func nucleiProduct(path, tags string) string {
	var products []string
	seen := map[string]bool{}
	for _, tag := range strings.Split(strings.ToLower(tags), ",") {
		tag = strings.TrimSpace(tag)
		if tag == "" || nonProductTags[tag] || strings.HasPrefix(tag, "cve") || yearRE.MatchString(tag) || seen[tag] {
			continue
		}
		seen[tag] = true
		products = append(products, productLabel(tag))
		if len(products) == 3 {
			break
		}
	}
	if len(products) > 0 {
		return strings.Join(products, ", ")
	}
	parts := strings.Split(strings.ToLower(path), "/")
	for _, part := range parts[1:] {
		if _, generic := map[string]bool{"cves": true, "cnvd": true, "vulnerabilities": true, "misconfiguration": true, "misconfig": true, "exposures": true, "technologies": true, "default-logins": true, "exposed-panels": true, "other": true, "others": true, "generic": true}[part]; !generic && !yearRE.MatchString(part) && !strings.HasPrefix(part, "cve-") {
			return productLabel(part)
		}
	}
	return "Не определён"
}

func nseTypeNames(categories []string) string {
	names := map[string]string{
		"auth": "Аутентификация", "broadcast": "Широковещательная разведка", "brute": "Подбор учётных данных",
		"default": "Стандартные проверки", "discovery": "Обнаружение", "dos": "Отказ в обслуживании",
		"exploit": "Эксплойты", "external": "Внешние источники", "fuzzer": "Fuzzing", "intrusive": "Интенсивные проверки",
		"malware": "Проверки на malware", "safe": "Безопасные проверки", "version": "Определение версий", "vuln": "Уязвимости",
		"info": "Информация",
	}
	var out []string
	for _, category := range categories {
		if label := names[strings.ToLower(category)]; label != "" {
			out = append(out, label)
		} else if category != "" {
			out = append(out, productLabel(category))
		}
	}
	if len(out) == 0 {
		return "Без категории"
	}
	return strings.Join(out, ", ")
}

func nseProduct(filename string) string {
	stem := strings.TrimSuffix(filename, filepath.Ext(filename))
	prefix := stem
	if i := strings.IndexByte(stem, '-'); i > 0 {
		prefix = stem[:i]
	}
	groups := map[string]string{
		"http": "HTTP веб-сервисы", "https": "HTTP веб-сервисы", "smb": "SMB и Windows", "smb2": "SMB и Windows", "samba": "SMB и Windows",
		"mysql": "Базы данных", "oracle": "Базы данных", "pgsql": "Базы данных", "db2": "Базы данных", "informix": "Базы данных", "maxdb": "Базы данных", "mongodb": "Базы данных", "redis": "Базы данных", "cassandra": "Базы данных", "couchdb": "Базы данных", "memcached": "Базы данных",
		"smtp": "Почтовые сервисы", "imap": "Почтовые сервисы", "pop3": "Почтовые сервисы", "snmp": "Сетевое управление · SNMP",
		"dns": "DNS", "ftp": "FTP и TFTP", "tftp": "FTP и TFTP", "ssh": "Удалённый доступ", "ssh2": "Удалённый доступ", "rdp": "Удалённый доступ", "telnet": "Удалённый доступ", "vnc": "Удалённый доступ", "rlogin": "Удалённый доступ",
		"ssl": "TLS/SSL", "ssl2": "TLS/SSL", "sslv2": "TLS/SSL", "tls": "TLS/SSL", "ldap": "Каталоги и аутентификация", "krb5": "Каталоги и аутентификация", "auth": "Каталоги и аутентификация",
		"broadcast": "Сетевая разведка", "targets": "Сетевая разведка", "ip": "Сетевая разведка", "ipv6": "Сетевая разведка", "resolveall": "Сетевая разведка", "hostmap": "Сетевая разведка",
		"modbus": "Промышленные и IoT протоколы", "bacnet": "Промышленные и IoT протоколы", "profinet": "Промышленные и IoT протоколы", "s7": "Промышленные и IoT протоколы", "iec": "Промышленные и IoT протоколы", "mqtt": "Промышленные и IoT протоколы", "coap": "Промышленные и IoT протоколы",
	}
	if group := groups[strings.ToLower(prefix)]; group != "" {
		return group
	}
	return productLabel(prefix)
}

func productLabel(value string) string {
	if value == "" {
		return "Не определён"
	}
	r := []rune(value)
	return strings.ToUpper(string(r[:1])) + string(r[1:])
}

func hasNucleiDocument(b []byte) bool {
	for _, line := range strings.SplitN(string(b), "\n", 80) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id:") {
			return true
		}
		if strings.HasPrefix(line, "info:") || strings.HasPrefix(line, "workflows:") {
			return false
		}
	}
	return false
}
