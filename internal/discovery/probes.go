package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2/v2"
	"wscan/internal/domain"
)

type serviceSignature struct {
	name, product, version         string
	info, hostname, osName, device string
	cpe                            []string
	soft                           bool
	expression                     *regexp2.Regexp
}

type serviceProbe struct {
	protocol, name  string
	payload         []byte
	ports, sslports map[int]bool
	rarity          int
	fallback        []string
	rules           []serviceSignature
}

// ProbeReport accounts for every rule; rejected rules are never silently lost.
type ProbeReport struct {
	Probes     int      `json:"probes"`
	Signatures int      `json:"signatures"`
	Loaded     int      `json:"loaded"`
	Errors     []string `json:"errors,omitempty"`
}

type probeDatabase struct {
	probes   []*serviceProbe
	byName   map[string]*serviceProbe
	excluded map[string]map[int]bool
	report   ProbeReport
}

var probeCache = struct {
	sync.Mutex
	path     string
	modified int64
	size     int64
	db       *probeDatabase
}{}

func loadProbes(libraryDir string) *probeDatabase {
	path := filepath.Join(libraryDir, "nmap", "nmap-service-probes")
	info, err := os.Stat(path)
	if err != nil {
		return &probeDatabase{report: ProbeReport{Errors: []string{err.Error()}}}
	}
	probeCache.Lock()
	defer probeCache.Unlock()
	if probeCache.db != nil && probeCache.path == path && probeCache.modified == info.ModTime().UnixNano() && probeCache.size == info.Size() {
		return probeCache.db
	}
	f, err := os.Open(path)
	if err != nil {
		return &probeDatabase{report: ProbeReport{Errors: []string{err.Error()}}}
	}
	defer f.Close()
	db := parseProbes(f)
	probeCache.path, probeCache.modified, probeCache.size, probeCache.db = path, info.ModTime().UnixNano(), info.Size(), db
	return db
}

func ServiceProbeReport(libraryDir string) ProbeReport { return loadProbes(libraryDir).report }

// delimited reads Nmap's q|...|, m|...| and version-field syntax.
func delimited(s string) (string, string, error) {
	if len(s) == 0 {
		return "", "", fmt.Errorf("missing delimiter")
	}
	delim := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == delim {
			return s[1:i], s[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("unterminated field")
}

func probePorts(s string) map[int]bool {
	m := map[int]bool{}
	for _, p := range ParsePortList(s) {
		m[p] = true
	}
	return m
}

// decodeProbe preserves bytes, including non-UTF8 protocol payloads.
func decodeProbe(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("trailing escape")
		}
		switch s[i] {
		case '0':
			out = append(out, 0)
		case 'a':
			out = append(out, 7)
		case 'b':
			out = append(out, 8)
		case 'f':
			out = append(out, 12)
		case 'n':
			out = append(out, 10)
		case 'r':
			out = append(out, 13)
		case 't':
			out = append(out, 9)
		case 'v':
			out = append(out, 11)
		case 'x':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("short hex escape")
			}
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(n))
			i += 2
		default:
			out = append(out, s[i])
		}
	}
	return out, nil
}

func parseProbes(reader io.Reader) *probeDatabase {
	db := &probeDatabase{byName: map[string]*serviceProbe{}, excluded: map[string]map[int]bool{"tcp": {}, "udp": {}}}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var current *serviceProbe
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) < 2 {
			continue
		}
		directive, rest := fields[0], strings.TrimSpace(fields[1])
		fail := func(err error) {
			db.report.Errors = append(db.report.Errors, fmt.Sprintf("line %d: %v", lineNumber, err))
		}
		switch directive {
		case "Exclude":
			protocols := []string{"tcp", "udp"}
			for _, item := range strings.Split(rest, ",") {
				if strings.HasPrefix(item, "T:") {
					protocols = []string{"tcp"}
					item = item[2:]
				} else if strings.HasPrefix(item, "U:") {
					protocols = []string{"udp"}
					item = item[2:]
				}
				for _, proto := range protocols {
					for p := range probePorts(item) {
						db.excluded[proto][p] = true
					}
				}
			}
		case "Probe":
			f := strings.SplitN(rest, " ", 3)
			current = nil
			if len(f) != 3 || !strings.HasPrefix(f[2], "q") {
				fail(fmt.Errorf("invalid probe"))
				continue
			}
			payload, _, err := delimited(f[2][1:])
			if err != nil {
				fail(err)
				continue
			}
			bytes, err := decodeProbe(payload)
			if err != nil {
				fail(err)
				continue
			}
			current = &serviceProbe{protocol: strings.ToLower(f[0]), name: f[1], payload: bytes, rarity: 1}
			db.probes = append(db.probes, current)
			db.byName[current.protocol+":"+current.name] = current
			db.report.Probes++
		case "ports", "sslports", "rarity", "fallback":
			if current == nil {
				continue
			}
			switch directive {
			case "ports":
				current.ports = probePorts(rest)
			case "sslports":
				current.sslports = probePorts(rest)
			case "rarity":
				current.rarity, _ = strconv.Atoi(rest)
			case "fallback":
				current.fallback = strings.Split(rest, ",")
			}
		case "match", "softmatch":
			db.report.Signatures++
			if current == nil {
				fail(fmt.Errorf("rule without probe"))
				continue
			}
			f := strings.SplitN(rest, " ", 2)
			if len(f) != 2 || !strings.HasPrefix(f[1], "m") {
				fail(fmt.Errorf("invalid rule"))
				continue
			}
			pattern, tail, err := delimited(f[1][1:])
			if err != nil {
				fail(err)
				continue
			}
			flags, metadata, _ := strings.Cut(tail, " ")
			options := regexp2.RE2
			if strings.Contains(flags, "i") {
				options |= regexp2.IgnoreCase
			}
			if strings.Contains(flags, "s") {
				options |= regexp2.Singleline
			}
			expression, err := regexp2.Compile(pattern, options)
			if err != nil {
				fail(err)
				continue
			}
			expression.MatchTimeout = 25 * time.Millisecond
			rule := serviceSignature{name: f[0], soft: directive == "softmatch", expression: expression}
			for metadata = strings.TrimSpace(metadata); metadata != ""; metadata = strings.TrimSpace(metadata) {
				key := metadata[:1]
				offset := 1
				if strings.HasPrefix(metadata, "cpe:") {
					key = "cpe"
					offset = 4
				}
				value, remaining, err := delimited(metadata[offset:])
				if err != nil {
					fail(err)
					break
				}
				if key == "p" {
					rule.product = value
				}
				if key == "v" {
					rule.version = value
				}
				switch key {
				case "i":
					rule.info = value
				case "h":
					rule.hostname = value
				case "o":
					rule.osName = value
				case "d":
					rule.device = value
				case "cpe":
					rule.cpe = append(rule.cpe, "cpe:/"+value)
				}
				metadata = remaining
				if key == "cpe" && strings.HasPrefix(metadata, "a") {
					metadata = metadata[1:]
				}
			}
			current.rules = append(current.rules, rule)
			db.report.Loaded++
		}
	}
	if err := scanner.Err(); err != nil {
		db.report.Errors = append(db.report.Errors, err.Error())
	}
	return db
}

var signatureVariable = regexp.MustCompile(`\$(?:SUBST\(\s*(\d+)\s*,\s*"((?:\\.|[^"\\])*)"\s*,\s*"((?:\\.|[^"\\])*)"\s*\)|P\((\d+)\)|I\((\d+),"([<>])"\)|(\d+))`)

func signatureValue(template string, match *regexp2.Match) string {
	return signatureVariable.ReplaceAllStringFunc(template, func(token string) string {
		f := signatureVariable.FindStringSubmatch(token)
		indexText := f[7]
		if f[1] != "" {
			indexText = f[1]
		}
		if f[4] != "" {
			indexText = f[4]
		}
		if f[5] != "" {
			indexText = f[5]
		}
		index, _ := strconv.Atoi(indexText)
		group := match.GroupByNumber(index)
		if group == nil {
			return ""
		}
		value := group.String()
		if f[1] != "" {
			a, _ := decodeProbe(f[2])
			b, _ := decodeProbe(f[3])
			value = strings.ReplaceAll(value, string(a), string(b))
		}
		if f[4] != "" {
			value = strings.Map(func(r rune) rune {
				if r < 32 || r > 126 {
					return -1
				}
				return r
			}, value)
		}
		if f[5] != "" {
			runes := []rune(value)
			if len(runes) > 8 {
				return ""
			}
			var n uint64
			if f[6] == "<" {
				for i := len(runes) - 1; i >= 0; i-- {
					n = (n << 8) | uint64(byte(runes[i]))
				}
			} else {
				for _, r := range runes {
					n = (n << 8) | uint64(byte(r))
				}
			}
			value = strconv.FormatUint(n, 10)
		}
		return value
	})
}

func signatureCPE(template string, match *regexp2.Match) string {
	return signatureVariable.ReplaceAllStringFunc(template, func(token string) string {
		value := strings.ToLower(signatureValue(token, match))
		value = strings.ReplaceAll(value, " ", "_")
		var out strings.Builder
		for _, r := range value {
			if strings.ContainsRune(`\\:?!*()`, r) {
				out.WriteByte('\\')
			}
			out.WriteRune(r)
		}
		return out.String()
	})
}

func (db *probeDatabase) match(ctx context.Context, probe *serviceProbe, response []byte, service domain.Service) (domain.Service, bool) {
	runes := make([]rune, len(response))
	for i, b := range response {
		runes[i] = rune(b)
	}
	var soft *serviceSignature
	visited := map[string]bool{}
	var rules []*serviceProbe
	var add func(*serviceProbe)
	add = func(p *serviceProbe) {
		if p == nil || visited[p.protocol+":"+p.name] {
			return
		}
		visited[p.protocol+":"+p.name] = true
		rules = append(rules, p)
		for _, name := range p.fallback {
			add(db.byName[p.protocol+":"+name])
		}
	}
	add(probe)
	add(db.byName[probe.protocol+":NULL"])
	for _, p := range rules {
		for i := range p.rules {
			if ctx.Err() != nil {
				return service, false
			}
			rule := &p.rules[i]
			match, err := rule.expression.FindRunesMatch(runes)
			if err != nil || match == nil {
				continue
			}
			if rule.soft {
				if soft == nil {
					soft = rule
				}
				continue
			}
			previousName := service.Name
			service.Name = rule.name
			if strings.HasPrefix(service.Name, "ssl/") {
				service.Name = strings.TrimPrefix(service.Name, "ssl/")
				service.Tunnel = "ssl"
			}
			if service.Name != previousName && !(previousName == "https" && service.Name == "http") {
				service.Product, service.Version = "", ""
			}
			product := signatureValue(rule.product, match)
			version := signatureValue(rule.version, match)
			if product != "" {
				if product != service.Product {
					service.Version = ""
				}
				service.Product = product
			}
			if version != "" {
				service.Version = version
			}
			service.Info = signatureValue(rule.info, match)
			service.DetectedHostname = signatureValue(rule.hostname, match)
			service.OS = signatureValue(rule.osName, match)
			service.DeviceType = signatureValue(rule.device, match)
			service.CPE = nil
			for _, cpe := range rule.cpe {
				service.CPE = append(service.CPE, signatureCPE(cpe, match))
			}
			service.FingerprintProbe = probe.name
			if service.Tunnel == "ssl" && service.Name == "http" {
				service.Name = "https"
			}
			return service, true
		}
	}
	if soft != nil {
		service.Name = soft.name
	}
	return service, false
}

func identifyProbeService(ctx context.Context, service domain.Service, libraryDir string, timeout time.Duration, rateTick <-chan time.Time) domain.Service {
	db := loadProbes(libraryDir)
	if len(db.probes) == 0 || db.excluded[service.Protocol][service.Port] {
		return service
	}
	// Bound network and regex work for each selected endpoint; never follow URLs
	// or use a port supplied by a signature. Signature data is not executable code.
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if timeout <= 0 || timeout > time.Second {
		timeout = time.Second
	}
	var probes []*serviceProbe
	for _, p := range db.probes {
		if p.protocol != service.Protocol {
			continue
		}
		if p.rarity <= 7 || p.ports[service.Port] || p.sslports[service.Port] {
			probes = append(probes, p)
		}
	}
	priority := func(p *serviceProbe) int {
		if isHTTPService(service) {
			switch p.name {
			case "GetRequest":
				return -5
			case "HTTPOptions":
				return -4
			case "FourOhFourRequest":
				return -3
			}
		}
		if p.name == "NULL" {
			return -2
		}
		if p.ports[service.Port] || p.sslports[service.Port] {
			return -1
		}
		return p.rarity
	}
	sort.SliceStable(probes, func(i, j int) bool { return priority(probes[i]) < priority(probes[j]) })
	attempts := 0
	for _, p := range probes {
		if attempts >= 8 || ctx.Err() != nil {
			break
		}
		if isHTTPService(service) && p.name != "GetRequest" && p.name != "HTTPOptions" && p.name != "FourOhFourRequest" && p.name != "NULL" {
			continue
		}
		if !waitProbe(ctx, rateTick) {
			break
		}
		attempts++
		probeCtx, stop := context.WithTimeout(ctx, timeout)
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(probeCtx, service.Protocol, net.JoinHostPort(service.Host, strconv.Itoa(service.Port)))
		if err != nil {
			stop()
			continue
		}
		deadline, _ := probeCtx.Deadline()
		_ = conn.SetDeadline(deadline)
		if service.Tunnel == "ssl" && service.Protocol == "tcp" {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: service.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
			if err = tlsConn.HandshakeContext(probeCtx); err != nil {
				_ = conn.Close()
				stop()
				continue
			}
			conn = tlsConn
		}
		if len(p.payload) > 0 {
			_, err = conn.Write(p.payload)
		}
		var response []byte
		if err == nil {
			if service.Protocol == "udp" {
				buf := make([]byte, 65535)
				n, _ := conn.Read(buf)
				response = buf[:n]
			} else {
				response, _ = io.ReadAll(io.LimitReader(conn, 64<<10))
			}
		}
		_ = conn.Close()
		stop()
		if len(response) == 0 {
			continue
		}
		previousName := service.Name
		found, hard := db.match(ctx, p, response, service)
		service = found
		if hard && service.Name != "ssl" && service.Product != "" {
			return service
		}
		if hard && service.Name == "ssl" {
			service.Tunnel = "ssl"
			// TLS identifies a transport, not HTTP. Keep an existing protocol
			// hint until an application signature identifies what is inside.
			if previousName != "" && previousName != "ssl" {
				service.Name = previousName
			}
		}
	}
	return service
}
