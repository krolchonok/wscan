package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antchfx/htmlquery"
	xhtml "golang.org/x/net/html"
)

// SQLiFormOptions задаёт параметры нативной проверки HTML-форм на SQL-инъекции
// (error-based, boolean-based blind и time-based blind) без внешних
// зависимостей типа sqlmap — движок сам парсит формы со страницы и фуззит
// каждое поле.
type SQLiFormOptions struct {
	URL, VirtualHost, Cookie string
	Insecure                 bool
	Timeout                  time.Duration
	Concurrency              int
}
type SQLiFormHit struct {
	FormURL, Action, Method, Parameter string
	Technique, DBMS, Payload, Evidence string
}
type SQLiFormProgress struct {
	Done, Total int
	Hit         *SQLiFormHit
}
type SQLiFormResult struct {
	Forms, Params, Done, Total, Errors int
	Hits                               []SQLiFormHit
	Limitation                         string
}

const (
	sqliMaxForms      = 20
	sqliMaxJobs       = 300
	sqliMaxBodyBytes  = 1 << 20
	sqliTimeDelay     = 4 * time.Second
	sqliTimeThreshold = 3500 * time.Millisecond
)

var sqliErrorSignatures = []struct {
	dbms string
	re   *regexp.Regexp
}{
	{"MySQL/MariaDB", regexp.MustCompile(`(?i)SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result|MySqlClient\.|check the manual that corresponds to your (MySQL|MariaDB) server`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)PostgreSQL.*ERROR|Warning.*\Wpg_|valid PostgreSQL result|Npgsql\.`)},
	{"MSSQL", regexp.MustCompile(`(?i)Driver.* SQL[ _-]*Server|OLE DB.* SQL Server|SQL Server.*Driver|Warning.*mssql_|ODBC SQL Server Driver|SQLServer JDBC Driver|System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the character string`)},
	{"Oracle", regexp.MustCompile(`(?i)\bORA-[0-9]{4,5}|Oracle error|Oracle.*Driver|Warning.*\Woci_|Warning.*\Wora_`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|Warning.*sqlite_|\[SQLITE_ERROR\]`)},
	{"generic", regexp.MustCompile(`(?i)SQL syntax.*(right|near)|quoted string not properly terminated|unterminated quoted string|syntax error at or near`)},
}

var sqliErrorPayloads = []string{`'`, `"`, `\`, `')`}

type sqliBooleanPair struct{ trueVal, falseVal string }

var sqliBooleanPairs = []sqliBooleanPair{
	{`' OR '1'='1'-- -`, `' OR '1'='2'-- -`},
	{`1 OR 1=1-- -`, `1 OR 1=2-- -`},
}

type sqliTimeProbe struct {
	dbms  string
	delay func(time.Duration) string
	zero  string
}

var sqliTimeProbes = []sqliTimeProbe{
	{"MySQL/MariaDB", func(d time.Duration) string { return fmt.Sprintf("' AND SLEEP(%d)-- -", int(d.Seconds())) }, "' AND SLEEP(0)-- -"},
	{"MSSQL", func(d time.Duration) string { return fmt.Sprintf("'; WAITFOR DELAY '0:0:%02d'--", int(d.Seconds())) }, "'; WAITFOR DELAY '0:0:00'--"},
	{"PostgreSQL", func(d time.Duration) string { return fmt.Sprintf("'; SELECT PG_SLEEP(%d);--", int(d.Seconds())) }, "'; SELECT PG_SLEEP(0);--"},
}

type sqliForm struct {
	Action *url.URL
	Method string
	Order  []string
	Values map[string]string
}

// parseSQLiForms находит на странице формы с method=get/post (без
// multipart/form-data) и собирает упорядоченный список полей с их
// исходными значениями — это и есть цели для фуззинга.
func parseSQLiForms(base *url.URL, body []byte) []sqliForm {
	doc, err := htmlquery.Parse(bytes.NewReader(body))
	if err != nil || doc == nil {
		return nil
	}
	nodes, err := htmlquery.QueryAll(doc, "//form")
	if err != nil {
		return nil
	}
	forms := make([]sqliForm, 0, len(nodes))
	for _, node := range nodes {
		if len(forms) >= sqliMaxForms {
			break
		}
		if strings.Contains(strings.ToLower(htmlquery.SelectAttr(node, "enctype")), "multipart") {
			continue
		}
		method := "GET"
		if strings.EqualFold(strings.TrimSpace(htmlquery.SelectAttr(node, "method")), "post") {
			method = "POST"
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
		if !sameWebOrigin(base, action) {
			continue
		}
		form := sqliForm{Action: action, Method: method, Values: map[string]string{}}
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
			if field.Data == "input" {
				switch typ {
				case "submit", "button", "reset", "image", "file":
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
		if len(form.Order) == 0 {
			continue
		}
		forms = append(forms, form)
	}
	return forms
}
func sqliSelectedOption(selectNode *xhtml.Node) string {
	options, err := htmlquery.QueryAll(selectNode, ".//option")
	if err != nil || len(options) == 0 {
		return ""
	}
	first := ""
	for i, opt := range options {
		v := htmlquery.SelectAttr(opt, "value")
		if v == "" {
			v = strings.TrimSpace(htmlquery.InnerText(opt))
		}
		if i == 0 {
			first = v
		}
		if htmlquery.ExistsAttr(opt, "selected") {
			return v
		}
	}
	return first
}
func sqliBodyDiffRatio(a, b string) float64 {
	la, lb := len(a), len(b)
	big := la
	if lb > big {
		big = lb
	}
	if big == 0 {
		return 0
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	return float64(diff) / float64(big)
}

// ScanSQLiForms загружает страницу o.URL, находит на ней формы и фуззит
// каждое поле поочерёдно (error-based, затем boolean-based blind, затем
// time-based blind), сравнивая ответ с базовым запросом формы. Это полностью
// нативная проверка — без вызова внешних инструментов типа sqlmap.
func ScanSQLiForms(ctx context.Context, o SQLiFormOptions, progress func(SQLiFormProgress)) (SQLiFormResult, error) {
	result := SQLiFormResult{}
	base, err := url.Parse(o.URL)
	if err != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return result, fmt.Errorf("укажи HTTP/HTTPS URL без учётных данных")
	}
	if strings.ContainsAny(o.VirtualHost, "/\\\r\n\t ") || strings.Contains(o.VirtualHost, ":") {
		return result, fmt.Errorf("virtual host: только имя без порта и пути")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	workers := o.Concurrency
	if workers < 1 {
		workers = 4
	}
	if workers > 8 {
		workers = 8
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout + sqliTimeDelay + 5*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, target, body string) (int, string, time.Duration, error) {
		if err := ctx.Err(); err != nil {
			return 0, "", 0, err
		}
		var reqBody io.Reader
		if body != "" {
			reqBody = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
		if err != nil {
			return 0, "", 0, err
		}
		req.Header.Set("User-Agent", "wscan-sqli-form")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if o.VirtualHost != "" {
			req.Host = o.VirtualHost
		}
		if o.Cookie != "" {
			req.Header.Set("Cookie", o.Cookie)
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", time.Since(start), err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, sqliMaxBodyBytes))
		elapsed := time.Since(start)
		if err != nil {
			return resp.StatusCode, "", elapsed, err
		}
		return resp.StatusCode, string(data), elapsed, nil
	}
	pageStatus, pageBody, _, err := do(http.MethodGet, base.String(), "")
	if err != nil {
		return result, fmt.Errorf("не удалось загрузить страницу: %w", err)
	}
	if pageStatus < 200 || pageStatus >= 400 {
		return result, fmt.Errorf("страница вернула HTTP %d", pageStatus)
	}
	forms := parseSQLiForms(base, []byte(pageBody))
	result.Forms = len(forms)
	if len(forms) == 0 {
		return result, fmt.Errorf("на странице не найдено подходящих форм (method=get/post, без multipart)")
	}
	buildRequest := func(f sqliForm, override string, overrideName string) (method, target, body string) {
		values := url.Values{}
		for _, name := range f.Order {
			v := f.Values[name]
			if name == overrideName {
				v = override
			}
			values.Set(name, v)
		}
		if f.Method == "POST" {
			return http.MethodPost, f.Action.String(), values.Encode()
		}
		copyURL := *f.Action
		q := copyURL.Query()
		for k, v := range values {
			q[k] = v
		}
		copyURL.RawQuery = q.Encode()
		return http.MethodGet, copyURL.String(), ""
	}
	type baseline struct {
		status  int
		body    string
		elapsed time.Duration
		ok      bool
	}
	baselines := make([]baseline, len(forms))
	for i, f := range forms {
		method, target, body := buildRequest(f, "", "")
		status, respBody, elapsed, err := do(method, target, body)
		if err != nil {
			continue
		}
		baselines[i] = baseline{status, respBody, elapsed, true}
	}
	type job struct {
		formIndex int
		param     string
	}
	var jobs []job
collect:
	for fi, f := range forms {
		for _, name := range f.Order {
			if len(jobs) >= sqliMaxJobs {
				result.Limitation = fmt.Sprintf("Проверка ограничена %d параметрами (найдено больше); увеличь точечно через повторный запуск", sqliMaxJobs)
				break collect
			}
			jobs = append(jobs, job{fi, name})
		}
	}
	result.Params = len(jobs)
	result.Total = len(jobs)
	testParam := func(fi int, param string) (*SQLiFormHit, bool) {
		f := forms[fi]
		bl := baselines[fi]
		if !bl.ok {
			return nil, true
		}
		run := func(value string) (int, string, time.Duration, error) {
			method, target, body := buildRequest(f, value, param)
			return do(method, target, body)
		}
		hit := func(technique, dbms, payload, evidence string) *SQLiFormHit {
			return &SQLiFormHit{FormURL: base.String(), Action: f.Action.String(), Method: f.Method, Parameter: param, Technique: technique, DBMS: dbms, Payload: payload, Evidence: evidence}
		}
		for _, payload := range sqliErrorPayloads {
			status, body, _, err := run(payload)
			if err != nil {
				continue
			}
			for _, sig := range sqliErrorSignatures {
				if sig.re.MatchString(body) && !sig.re.MatchString(bl.body) {
					return hit("error-based", sig.dbms, payload, fmt.Sprintf("сигнатура ошибки БД (%s) в ответе на payload (HTTP %d); baseline без неё (HTTP %d)", sig.dbms, status, bl.status)), false
				}
			}
		}
		for _, pair := range sqliBooleanPairs {
			trueStatus, trueBody, _, err1 := run(pair.trueVal)
			if err1 != nil {
				continue
			}
			falseStatus, falseBody, _, err2 := run(pair.falseVal)
			if err2 != nil {
				continue
			}
			statusDiffers := trueStatus != falseStatus
			if trueStatus == bl.status && sqliBodyDiffRatio(bl.body, trueBody) <= 0.03 && (statusDiffers || sqliBodyDiffRatio(bl.body, falseBody) >= 0.12) && (statusDiffers || sqliBodyDiffRatio(trueBody, falseBody) >= 0.12) {
				return hit("boolean-based blind", "", pair.trueVal+" / "+pair.falseVal, fmt.Sprintf("true-условие похоже на baseline (HTTP %d, %d байт vs %d), false-условие отличается (HTTP %d, %d байт)", bl.status, len(trueBody), len(bl.body), falseStatus, len(falseBody))), false
			}
		}
		for _, probe := range sqliTimeProbes {
			_, _, zeroElapsed, zeroErr := run(probe.zero)
			if zeroErr != nil || zeroElapsed >= bl.elapsed+sqliTimeThreshold {
				continue
			}
			confirmed := true
			var last time.Duration
			for attempt := 0; attempt < 2; attempt++ {
				_, _, elapsed, err := run(probe.delay(sqliTimeDelay))
				if err != nil || elapsed < bl.elapsed+sqliTimeThreshold {
					confirmed = false
					break
				}
				last = elapsed
			}
			if confirmed {
				return hit("time-based blind", probe.dbms, probe.delay(sqliTimeDelay), fmt.Sprintf("запрос с задержкой занял %s (контроль без задержки %s, baseline %s)", last, zeroElapsed, bl.elapsed)), false
			}
		}
		return nil, false
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
				h, errored := testParam(j.formIndex, j.param)
				mu.Lock()
				event := SQLiFormProgress{Done: int(done.Add(1)), Total: result.Total}
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
