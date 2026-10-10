package template

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"wscan/internal/domain"
	"wscan/internal/jsapi"
)

var expressionRE = regexp.MustCompile(`\{\{([^}]+)\}\}`)

func Parse(data []byte, source string) (domain.Template, error) {
	var t domain.Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return t, fmt.Errorf("parse YAML: %w", err)
	}
	t.Raw = append([]byte(nil), data...)
	t.Source, t.Compatible = source, true
	if t.ID == "" {
		t.Unsupported = append(t.Unsupported, "missing id")
	}
	if len(t.HTTP) == 0 && len(t.TCP) == 0 && len(t.Network) == 0 && len(t.DNS) == 0 && len(t.SSL) == 0 && len(t.Workflows) == 0 && len(t.Code) == 0 && len(t.JavaScript) == 0 {
		t.Unsupported = append(t.Unsupported, "no supported protocol requests (http/tcp/network/dns/ssl/workflows/code/javascript)")
	}
	for i, req := range t.Code {
		if len(req.Engine) == 0 {
			t.Unsupported = append(t.Unsupported, fmt.Sprintf("code[%d] has no engine", i))
		}
		if FindInterpreter(req.Engine) == "" {
			t.Unsupported = append(t.Unsupported, fmt.Sprintf("code[%d]: no interpreter found on this machine (tried: %s)", i, strings.Join(req.Engine, ", ")))
		}
	}
	for i, req := range t.JavaScript {
		if strings.TrimSpace(req.Code) == "" && strings.TrimSpace(req.PreCondition) == "" {
			t.Unsupported = append(t.Unsupported, fmt.Sprintf("javascript[%d] has no code", i))
		}
		for _, source := range []string{req.Init, req.PreCondition, req.Code} {
			for _, reason := range jsapi.CheckSource(source) {
				t.Unsupported = append(t.Unsupported, fmt.Sprintf("javascript[%d]: %s", i, reason))
			}
		}
		checkMatchers(req.Matchers, &t.Unsupported)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err == nil {
		unknownKeys(root, "template", []string{"id", "info", "http", "tcp", "network", "dns", "ssl", "workflows", "variables", "flow", "code", "javascript"}, &t.Unsupported)
		// flow and javascript both run on the embedded goja engine.
		// javascript: uses require("nuclei/…") helpers (internal/engine/js);
		// flow: only orchestrates http/tcp/network/dns/ssl blocks.
		// code: shells out — separate per-project opt-in (AllowCodeExec).
		for _, key := range []string{"headless", "websocket", "file", "whois"} {
			if _, ok := root[key]; ok {
				t.Unsupported = append(t.Unsupported, key+" protocol/feature is not supported")
			}
		}
		if requests, ok := root["http"].([]any); ok {
			for i, raw := range requests {
				request, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				// Behavior-changing fields must be implemented or rejected explicitly.
				for _, key := range []string{"pre-condition", "global-matchers", "digest-username", "digest-password", "read-all", "req-condition", "iterate-all"} {
					if value, exists := request[key]; exists && meaningfulValue(value) {
						t.Unsupported = append(t.Unsupported, fmt.Sprintf("http[%d]: %s is not implemented by the native engine", i, key))
					}
				}
				if value, ok := request["max-size"].(int); ok && value < 0 {
					t.Unsupported = append(t.Unsupported, fmt.Sprintf("http[%d]: max-size must not be negative", i))
				}
				if value, ok := request["max-redirects"].(int); ok && value < 0 {
					t.Unsupported = append(t.Unsupported, fmt.Sprintf("http[%d]: max-redirects must not be negative", i))
				}
				unknownKeys(request, fmt.Sprintf("http[%d]", i), []string{
					"method", "path", "raw", "headers", "body", "matchers", "matchers-condition", "extractors",
					"payloads", "attack", "threads",
					"redirects", "max-redirects", "host-redirects", "stop-at-first-match", "cookie-reuse",
					"req-condition", "iterate-all", "skip-variables-check", "max-request", "max-size",
					"read-all", "digest-username", "digest-password", "disable-cookie",
					// Accepted and ignored / best-effort: do not block the template.
					"pre-condition", "global-matchers", "disable-path-automerge", "id",
				}, &t.Unsupported)
				if matchers, ok := request["matchers"].([]any); ok {
					for j, item := range matchers {
						if matcher, ok := item.(map[string]any); ok {
							unknownKeys(matcher, fmt.Sprintf("http[%d].matchers[%d]", i, j), []string{"type", "part", "status", "words", "regex", "binary", "dsl", "xpath", "size", "condition", "negative", "case-insensitive", "name", "internal", "encoding"}, &t.Unsupported)
						}
					}
				}
				if extractors, ok := request["extractors"].([]any); ok {
					for j, item := range extractors {
						if extractor, ok := item.(map[string]any); ok {
							unknownKeys(extractor, fmt.Sprintf("http[%d].extractors[%d]", i, j), []string{"type", "name", "part", "regex", "group", "kval", "json", "dsl", "xpath", "attribute", "internal", "case-insensitive"}, &t.Unsupported)
						}
					}
				}
			}
		}
		if info, ok := root["info"].(map[string]any); ok {
			unknownKeys(info, "info", []string{"name", "author", "severity", "description", "reference", "metadata", "tags", "classification", "remediation", "impact", "verified", "shodan-query", "fofa-query", "censys-query", "max-requests", "vendor", "product", "http-requests"}, &t.Unsupported)
		}
	}
	for i := range t.HTTP {
		r := &t.HTTP[i]
		if r.Method == "" {
			r.Method = "GET"
		}
		if len(r.Path) == 0 && len(r.Raw) == 0 {
			t.Unsupported = append(t.Unsupported, fmt.Sprintf("http[%d] has no path", i))
		}
		for _, extractor := range r.Extractors {
			switch strings.ToLower(extractor.Type) {
			case "regex", "kval", "dsl", "json", "xpath":
			default:
				t.Unsupported = append(t.Unsupported, "extractor type "+extractor.Type+" is not supported")
			}
		}
		for _, path := range r.Path {
			for _, expr := range expressionRE.FindAllStringSubmatch(path, -1) {
				if !supportedExpression(strings.TrimSpace(expr[1]), t.Variables, r.Payloads) {
					t.Unsupported = append(t.Unsupported, "template expression {{"+expr[1]+"}} is not supported")
				}
			}
		}
		checkMatchers(r.Matchers, &t.Unsupported)
	}
	for _, r := range append(append([]domain.TCPRequest{}, t.TCP...), t.Network...) {
		if len(r.Inputs) == 0 && len(r.Host) == 0 {
			t.Unsupported = append(t.Unsupported, "tcp request has no inputs/host")
		}
		checkMatchers(r.Matchers, &t.Unsupported)
	}
	for _, r := range t.DNS {
		checkMatchers(r.Matchers, &t.Unsupported)
	}
	for _, r := range t.SSL {
		checkMatchers(r.Matchers, &t.Unsupported)
	}
	// A template needs a way to produce a result: matchers somewhere, or
	// non-empty extractors (Nuclei reports extractor-only templates when a
	// non-internal extractor succeeds). Multi-step (req-condition) templates
	// may leave early requests without matchers.
	if hasRequests(t) && totalMatchers(t) == 0 && totalExtractors(t) == 0 {
		t.Unsupported = append(t.Unsupported, "no matchers or extractors in any request")
	}
	if len(t.Unsupported) > 0 {
		t.Compatible = false
	}
	t.Risk = "active"
	readOnly := len(t.HTTP) > 0
	for _, req := range t.HTTP {
		method := strings.ToUpper(req.Method)
		if (method != "GET" && method != "HEAD") || req.Body != "" {
			readOnly = false
		}
	}
	if readOnly {
		t.Risk = "read-only"
	}
	if strings.Contains(","+strings.ToLower(t.Info.Tags)+",", ",intrusive,") {
		t.Risk = "intrusive"
	}
	if strings.Contains(","+strings.ToLower(t.Info.Tags)+",", ",exploit,") {
		t.Risk = "intrusive"
		t.IsExploit = true
	}
	return t, nil
}

// supportedExpression reports whether a {{...}} expression used in a request
// path can be resolved by the native engine: a target placeholder, a declared
// template variable, a randstr placeholder, or a generator/dsl function call.
func supportedExpression(expr string, vars domain.VariableList, payloads domain.PayloadSet) bool {
	switch expr {
	case "BaseURL", "RootURL", "Hostname", "Host", "Scheme", "Port", "Path", "interactsh-url",
		"FQDN", "RDN", "DN", "SD", "TLD":
		return true
	}
	if strings.HasPrefix(expr, "randstr") || strings.Contains(expr, "(") {
		return true
	}
	for _, v := range vars {
		if v.Name == expr {
			return true
		}
	}
	if _, ok := payloads[expr]; ok {
		return true
	}
	return false
}

func hasRequests(t domain.Template) bool {
	return len(t.HTTP)+len(t.TCP)+len(t.Network)+len(t.DNS)+len(t.SSL)+len(t.Code)+len(t.JavaScript) > 0
}

func totalMatchers(t domain.Template) int {
	n := 0
	for _, r := range t.HTTP {
		n += len(r.Matchers)
	}
	for _, r := range t.TCP {
		n += len(r.Matchers)
	}
	for _, r := range t.Network {
		n += len(r.Matchers)
	}
	for _, r := range t.DNS {
		n += len(r.Matchers)
	}
	for _, r := range t.SSL {
		n += len(r.Matchers)
	}
	for _, r := range t.Code {
		n += len(r.Matchers)
	}
	for _, r := range t.JavaScript {
		n += len(r.Matchers)
	}
	return n
}

func totalExtractors(t domain.Template) int {
	n := 0
	for _, r := range t.HTTP {
		n += len(r.Extractors)
	}
	for _, r := range t.TCP {
		n += len(r.Extractors)
	}
	for _, r := range t.Network {
		n += len(r.Extractors)
	}
	for _, r := range t.DNS {
		n += len(r.Extractors)
	}
	for _, r := range t.SSL {
		n += len(r.Extractors)
	}
	for _, r := range t.Code {
		n += len(r.Extractors)
	}
	for _, r := range t.JavaScript {
		n += len(r.Extractors)
	}
	return n
}

// checkMatchers flags any matcher whose type the native engine cannot evaluate.
func checkMatchers(matchers []domain.Matcher, unsupported *[]string) {
	for _, m := range matchers {
		switch strings.ToLower(m.Type) {
		case "status", "word", "regex", "binary", "dsl", "size", "xpath":
		default:
			*unsupported = append(*unsupported, "matcher type "+m.Type+" is not supported")
		}
	}
}

func unknownKeys(values map[string]any, where string, allowed []string, unsupported *[]string) {
	known := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		known[key] = struct{}{}
	}
	for key := range values {
		if _, ok := known[key]; !ok {
			*unsupported = append(*unsupported, fmt.Sprintf("%s field %q is not supported", where, key))
		}
	}
}

func Validate(t domain.Template) error {
	if t.ID == "" {
		return fmt.Errorf("template id is required")
	}
	if !t.Compatible {
		return fmt.Errorf("unsupported template features: %s", strings.Join(t.Unsupported, "; "))
	}
	return nil
}

func meaningfulValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}
