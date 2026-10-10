package domain

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"time"
)

type StringList []string

func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*s = []string{node.Value}
		return nil
	}
	var values []string
	if err := node.Decode(&values); err != nil {
		return err
	}
	*s = values
	return nil
}

// IntList is a network/TCP "port" field: nuclei allows a single port
// ("port: 6379"), a quoted single port ("port: \"6379\""), or a comma-separated
// list of ports to try ("port: 6379,6380"). A real port variable
// (e.g. "{{Port}}") is not a case seen in the library and is left unparsed
// (empty list); callers fall back to the target's own port in that case.
type IntList []int

func (s *IntList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!int" {
			var v int
			if err := node.Decode(&v); err != nil {
				return err
			}
			*s = []int{v}
			return nil
		}
		var out []int
		for _, part := range strings.Split(node.Value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil {
				// Not a plain port list (e.g. a template expression like
				// "{{Port}}") — leave it to the caller's fallback instead
				// of failing the whole template.
				*s = nil
				return nil
			}
			out = append(out, n)
		}
		*s = out
		return nil
	}
	var values []int
	if err := node.Decode(&values); err != nil {
		return fmt.Errorf("port list: %w", err)
	}
	*s = values
	return nil
}

type Project struct {
	ID                   int64
	Name                 string
	Targets              []string
	TemplateIDs          []string
	RPS                  int
	Concurrency          int
	TimeoutSeconds       int
	Retries              int
	DiscoveryEnabled     bool
	AllPorts             bool
	DiscoveryRPS         int
	DiscoveryConcurrency int
	// AllowCodeExec opts this project into running code: checks, which shell
	// out to a real external interpreter on the scanner's own machine —
	// unlike every other request type, this one leaves our native engine on
	// purpose. Defaults to false; the TUI requires an explicit warning
	// acknowledgement before it can become true (internal/tui/settings.go).
	AllowCodeExec bool
	// AllowExploit opts this project into running exploit: checks (tags
	// containing "exploit") — templates that actually trigger a vulnerability
	// against the target (command injection, auth bypass, path traversal, …),
	// not just detect it. Unlike code:, these stay inside the native engine
	// (http:/tcp:/javascript:), but they act on the target itself and can have
	// real side effects. Defaults to false; the TUI requires an explicit
	// warning acknowledgement before it can become true (internal/tui/settings.go).
	AllowExploit bool
	// AllowCredentialAttack opts this project into running credential
	// spray / login-validation checks (internal/engine.SprayCredentials).
	// Unlike AllowCodeExec/AllowExploit, this doesn't change what a template
	// does — it gates a separate engine entry point that tries real
	// credentials against real accounts and can trigger account lockout if
	// misused. Defaults to false; the TUI requires an explicit warning
	// acknowledgement before it can become true, same pattern as
	// AllowCodeExec/AllowExploit.
	AllowCredentialAttack bool
	// LockoutMaxAttempts/LockoutWindowMinutes bound SprayCredentials: once a
	// username has this many recorded failures within the trailing window,
	// every further attempt against it is skipped automatically — not just
	// warned about — for the rest of the spray, regardless of how many
	// targets or credentials remain. Zero means "use the conservative
	// default" (DefaultLockoutMaxAttempts / DefaultLockoutWindowMinutes),
	// not "unlimited": there is no project setting that disables this check.
	LockoutMaxAttempts   int
	LockoutWindowMinutes int
	ScanTargets          []string  `json:"-"`
	Services             []Service `json:"-"`
	UseDiscoveredTargets bool      `json:"-"`
}

// DefaultLockoutMaxAttempts / DefaultLockoutWindowMinutes are the
// conservative fallback lockout-safety policy applied when a project hasn't
// set its own (Project.LockoutMaxAttempts/LockoutWindowMinutes == 0). We
// have no way to know a target domain's real AD lockout policy up front, so
// the default errs toward caution rather than guessing a "typical" one.
const (
	DefaultLockoutMaxAttempts   = 3
	DefaultLockoutWindowMinutes = 30
)

// AuthAttempt is one result row from SprayCredentials: one credential tried
// against one target service.
type AuthAttempt struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	Domain   string `json:"domain,omitempty"`
	Success  bool   `json:"success"`
	// Skipped is true when the attempt was never sent because Username had
	// already reached the project's lockout-safety threshold (see
	// internal/storage.Store.RecentFailureCount) — this is the safety
	// mechanism working as intended, not a failure.
	Skipped bool   `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ModuleResult is one result row from Engine.RunModule: a named post-auth
// enumeration module run against one target with one credential. Data holds
// whatever shape that module returns (a *ldap.SearchResult, a share-name
// list, a WinRMOutput, ...) — it is JSON-marshalled as-is for storage/display,
// not given its own fixed schema, since the module catalog's shapes
// genuinely differ by protocol.
type ModuleResult struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Module   string `json:"module"`
	Data     any    `json:"data,omitempty"`
	Error    string `json:"error,omitempty"`
}

type Service struct {
	State    string `json:"state,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
	// PortService is a registry hint; Name is used for protocol routing.
	PortService string `json:"port_service,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
	// Target is the scope entry (domain, IP or URL) this service was found for.
	// Host holds the resolved address, so a domain target maps to its IPs.
	Target string `json:"target,omitempty"`
}

// Credential is one set of login material for post-auth checks (login
// validation / "spray" against SMB, SSH, MySQL, MSSQL, Postgres, VNC today;
// LDAP and WinRM planned). Stored in plaintext — this project's threat model
// treats the operator's own wscan.db as already-trusted local storage, the
// same way templates and findings are, so there is no separate encryption
// layer for Secret.
type Credential struct {
	ID        int64
	ProjectID int64
	// Type distinguishes the secret's shape: "password", "ntlm-hash", "ssh-key".
	Type     string
	Username string
	// Domain is the AD/NetBIOS domain this account belongs to, empty for a
	// local account. Two credentials can share Username across different
	// Domain values without colliding.
	Domain string
	Secret string
	Notes  string
}

type Matcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Status          []int    `yaml:"status"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Binary          []string `yaml:"binary"`
	DSL             []string `yaml:"dsl"`
	XPath           []string `yaml:"xpath"`
	Size            []int    `yaml:"size"`
	Condition       string   `yaml:"condition"`
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Name            string   `yaml:"name"`
	Internal        bool     `yaml:"internal"`
}

// Extractor pulls values out of a response for evidence, and (when Internal)
// exposes them as variables to later matchers/extractors of the same template.
type Extractor struct {
	Type      string   `yaml:"type"`
	Name      string   `yaml:"name"`
	Part      string   `yaml:"part"`
	Regex     []string `yaml:"regex"`
	Group     int      `yaml:"group"`
	KVal      []string `yaml:"kval"`
	JSON      []string `yaml:"json"`
	DSL       []string `yaml:"dsl"`
	XPath     []string `yaml:"xpath"`
	Attribute string   `yaml:"attribute"`
	Internal  bool     `yaml:"internal"`
}

type HTTPRequest struct {
	ID                string            `yaml:"id"` // optional; used by flow: http("name")
	Method            string            `yaml:"method"`
	Path              StringList        `yaml:"path"`
	Raw               StringList        `yaml:"raw"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	Matchers          []Matcher         `yaml:"matchers"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Extractors        []Extractor       `yaml:"extractors"`
	Payloads          PayloadSet        `yaml:"payloads"`
	Attack            string            `yaml:"attack"`
}

// Payload is one named payload source: an inline list of values, or a file path
// (wordlist) resolved at scan time.
type Payload struct {
	Values []string
	File   string
}

// PayloadSet maps a payload name to its source. A sequence node is an inline
// list; a scalar node is a file path.
type PayloadSet map[string]Payload

func (p *PayloadSet) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	set := PayloadSet{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		val := node.Content[i+1]
		switch val.Kind {
		case yaml.SequenceNode:
			var vs []string
			for _, item := range val.Content {
				vs = append(vs, item.Value)
			}
			set[name] = Payload{Values: vs}
		case yaml.ScalarNode:
			set[name] = Payload{File: val.Value}
		}
	}
	*p = set
	return nil
}

// Variable is one entry of a template's `variables:` block, kept in document
// order so a later variable can reference an earlier one.
type Variable struct {
	Name  string
	Value string
}

// VariableList preserves the order of a `variables:` mapping.
type VariableList []Variable

func (v *VariableList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		*v = append(*v, Variable{Name: node.Content[i].Value, Value: node.Content[i+1].Value})
	}
	return nil
}

type Template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string     `yaml:"name"`
		Severity    string     `yaml:"severity"`
		Tags        string     `yaml:"tags"`
		Description string     `yaml:"description"`
		Reference   StringList `yaml:"reference"`
	} `yaml:"info"`
	Variables VariableList    `yaml:"variables"`
	HTTP      []HTTPRequest   `yaml:"http"`
	TCP       []TCPRequest    `yaml:"tcp"`
	Network   []TCPRequest    `yaml:"network"`
	DNS       []DNSRequest    `yaml:"dns"`
	SSL       []SSLRequest    `yaml:"ssl"`
	Workflows []WorkflowEntry `yaml:"workflows"`
	// Flow is a JS orchestration script (a one-liner like "http(1) && http(2)"
	// or a multi-line block) that decides which http/tcp/network/dns/ssl
	// request block runs, in what order, instead of running all of them.
	// Executed by the embedded goja JS engine — see internal/engine/flow.go.
	Flow       string              `yaml:"flow"`
	Code       []CodeRequest       `yaml:"code"`
	JavaScript []JavaScriptRequest `yaml:"javascript"`
	Risk       string              `yaml:"-"`
	// IsExploit is set at parse time from an "exploit" tag (see
	// internal/template/parse.go) — the template triggers the vulnerability
	// instead of only detecting it. The engine requires the project's explicit
	// AllowExploit opt-in regardless of the supported request protocol.
	IsExploit   bool     `yaml:"-"`
	Source      string   `yaml:"-"`
	Raw         []byte   `yaml:"-"`
	Compatible  bool     `yaml:"-"`
	Complete    bool     `yaml:"-"`
	Unsupported []string `yaml:"-"`
}

// JavaScriptRequest is a javascript: check: run an embedded goja script with
// nuclei-compatible helpers (require("nuclei/net"), Export, isPortOpen, …)
// against the scan target. Unlike code:, this stays inside our process.
type JavaScriptRequest struct {
	// Init is JS run once, before payload expansion for this execution — real
	// templates use it to compute payload values dynamically (e.g. load SSH
	// private keys from a directory via require('nuclei/fs')) and feed them
	// back with updatePayload()/set() (see internal/engine/js/runtime.go's
	// RunInit). Unlike nuclei, which compiles a template once and runs init a
	// single time for its whole lifetime, our engine has no such cache, so
	// init runs once per execJavaScript call (once per target) instead of
	// once per template load — harmless for the deterministic cases observed
	// in the library (e.g. reading a fixed directory of key files).
	Init              string         `yaml:"init"`
	PreCondition      string         `yaml:"pre-condition"`
	Code              string         `yaml:"code"`
	Args              map[string]any `yaml:"args"`
	Payloads          PayloadSet     `yaml:"payloads"`
	Attack            string         `yaml:"attack"`
	Matchers          []Matcher      `yaml:"matchers"`
	MatchersCondition string         `yaml:"matchers-condition"`
	Extractors        []Extractor    `yaml:"extractors"`
	StopAtFirstMatch  bool           `yaml:"stop-at-first-match"`
	Threads           int            `yaml:"threads"`
}

type Finding struct {
	Description string    `json:"description,omitempty"`
	References  []string  `json:"references,omitempty"`
	MatcherName string    `json:"matcher_name,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Request     string    `json:"request,omitempty"`
	Response    string    `json:"response,omitempty"`
	TemplateID  string    `json:"template_id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Target      string    `json:"target"`
	MatchedAt   string    `json:"matched_at"`
	Evidence    string    `json:"evidence,omitempty"`
	Risk        string    `json:"risk"`
	Time        time.Time `json:"time"`
}

// WorkflowEntry references another template to run, with subtemplates that run
// only when it matches (optionally keyed by a named matcher).
type WorkflowEntry struct {
	Template     string            `yaml:"template"`
	Tags         string            `yaml:"tags"`
	Subtemplates []WorkflowEntry   `yaml:"subtemplates"`
	Matchers     []WorkflowMatcher `yaml:"matchers"`
}

type WorkflowMatcher struct {
	Name         string          `yaml:"name"`
	Subtemplates []WorkflowEntry `yaml:"subtemplates"`
}

// CodeRequest is a code: check: run source through a real external
// interpreter on the scanner's own machine and match its output. Unlike
// every other request type, this one does not stay inside our native
// engine — it shells out, so the engine only runs it when the operator has
// explicitly enabled code execution for the project (see
// engine.Config.AllowCodeExec) and the UI has shown the one-time warning.
type CodeRequest struct {
	Engine            []string    `yaml:"engine"`
	Source            string      `yaml:"source"`
	Args              []string    `yaml:"args"`
	Pattern           string      `yaml:"pattern"`
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Extractors        []Extractor `yaml:"extractors"`
}

// TCPRequest is a raw TCP/network check: send inputs over a connection and match
// the bytes read back.
type TCPRequest struct {
	Inputs            []TCPInput  `yaml:"inputs"`
	Host              StringList  `yaml:"host"`
	Port              IntList     `yaml:"port"`
	ReadSize          int         `yaml:"read-size"`
	UDP               bool        `yaml:"udp"` // dial UDP instead of TCP (nuclei network udp:)
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Extractors        []Extractor `yaml:"extractors"`
}

type TCPInput struct {
	Data string `yaml:"data"`
	Name string `yaml:"name"`
	Type string `yaml:"type"` // "hex" or text (default)
	Read int    `yaml:"read"`
}

// SSLRequest inspects a target's TLS certificate and matches its fields
// (subject_cn, subject_dn, issuer_dn, serial, not_before, not_after, ...).
type SSLRequest struct {
	Address           string      `yaml:"address"`
	MinVersion        string      `yaml:"min_version"`
	MaxVersion        string      `yaml:"max_version"`
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Extractors        []Extractor `yaml:"extractors"`
}

// DNSRequest is a DNS query check: resolve a name and match the answer.
type DNSRequest struct {
	Name              string      `yaml:"name"`
	Type              string      `yaml:"type"`  // A, AAAA, CNAME, MX, TXT, NS, ...
	Class             string      `yaml:"class"` // usually inet
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Extractors        []Extractor `yaml:"extractors"`
}

type Run struct {
	ID         int64     `json:"id"`
	ProjectID  int64     `json:"project_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"`
	Findings   []Finding `json:"findings,omitempty"`
	Services   []Service `json:"services,omitempty"`
}
