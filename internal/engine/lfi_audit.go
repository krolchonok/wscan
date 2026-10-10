package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"wscan/internal/domain"
)

type LFIOptions struct {
	URL, Parameter, VirtualHost string
	Insecure                    bool
}
type LFIResult struct {
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Method     string `json:"method"`
	Matched    *bool  `json:"matched"`
	Evidence   string `json:"evidence"`
	Requests   int    `json:"requests"`
	Limitation string `json:"limitation"`
}

var lfiPasswdRE = regexp.MustCompile(`(?m)(?:^|[>\r\n])root:[^:\r\n]*:0:0:[^\r\n]*`)

func CheckLFI(ctx context.Context, target domain.Service, o LFIOptions) (*LFIResult, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("нужен HTTP(S) URL без учётки в адресе")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	n, err := strconv.Atoi(port)
	if err != nil || n != target.Port {
		return nil, fmt.Errorf("URL должен использовать выбранный порт %d", target.Port)
	}
	if !strings.EqualFold(u.Hostname(), strings.Trim(target.Host, "[]")) {
		return nil, fmt.Errorf("URL должен использовать выбранный хост %s; виртуальный хост задаётся отдельно", target.Host)
	}
	if o.Parameter == "" || !u.Query().Has(o.Parameter) {
		return nil, fmt.Errorf("укажи существующий query-параметр URL")
	}
	if strings.ContainsAny(o.VirtualHost, "/\\\r\n\t ") || strings.Contains(o.VirtualHost, ":") {
		return nil, fmt.Errorf("virtual host: только имя без порта и пути")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	tlsName := u.Hostname()
	if o.VirtualHost != "" {
		tlsName = o.VirtualHost
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: tlsName, InsecureSkipVerify: o.Insecure}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result := &LFIResult{URL: u.Scheme + "://" + u.Host + u.EscapedPath(), Parameter: o.Parameter, Method: "контроль и ограниченное чтение системного файла", Limitation: "Проверяется один query-параметр; редиректы не выполняются. Отсутствие совпадения не исключает LFI."}
	const controlMissing = "wscan-lfi-control-file-does-not-exist"
	fetch := func(value *string) (string, error) {
		copyURL := *u
		if value != nil {
			q := copyURL.Query()
			q.Set(o.Parameter, *value)
			copyURL.RawQuery = q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, copyURL.String(), nil)
		if err != nil {
			return "", err
		}
		if o.VirtualHost != "" {
			req.Host = net.JoinHostPort(o.VirtualHost, strconv.Itoa(target.Port))
		}
		req.Header.Set("User-Agent", "wscan-lfi-audit")
		result.Requests++
		resp, err := client.Do(req)
		if err != nil {
			if requestErr, ok := err.(*url.Error); ok {
				return "", fmt.Errorf("HTTP: %w", requestErr.Err)
			}
			return "", err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
		if err != nil {
			return "", err
		}
		if len(data) > 65536 {
			return "", fmt.Errorf("ответ превышает 64 KiB: результат неопределён")
		}
		if (resp.StatusCode < 200 || resp.StatusCode >= 300) && !(value != nil && *value == controlMissing && resp.StatusCode >= 400 && resp.StatusCode != 401 && resp.StatusCode != 403) {
			return "", fmt.Errorf("HTTP %d: результат неопределён", resp.StatusCode)
		}
		return string(data), nil
	}
	original, err := fetch(nil)
	if err != nil {
		return result, err
	}
	missing := controlMissing
	control, err := fetch(&missing)
	if err != nil {
		return result, err
	}
	probes := []struct {
		value, label string
		match        func(string) bool
	}{
		{"../../../../../../../../etc/passwd", "Unix passwd: запись root с UID/GID 0", func(s string) bool { return lfiPasswdRE.MatchString(s) }},
		{"..\\..\\..\\..\\..\\..\\Windows\\win.ini", "Windows win.ini: секции extensions и fonts", func(s string) bool {
			s = strings.ToLower(s)
			return strings.Contains(s, "[extensions]") && strings.Contains(s, "[fonts]")
		}},
	}
	for _, p := range probes {
		if p.match(original) || p.match(control) {
			continue
		}
		body, err := fetch(&p.value)
		if err != nil {
			return result, err
		}
		if p.match(body) {
			confirmed := true
			result.Matched = &confirmed
			result.Evidence = p.label + " присутствует только в ответе на traversal; содержимое файла не сохранялось"
			return result, nil
		}
	}
	notConfirmed := false
	result.Matched = &notConfirmed
	result.Evidence = "Выполненные запросы не дали достаточного подтверждения LFI"
	return result, nil
}
