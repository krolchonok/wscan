package js

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Static SPF cost is a conservative upper bound, not check_host(ip,sender).
// Include branches may short-circuit; macros require the actual sender.
type spfAudit struct {
	ctx     context.Context
	lookup  func(context.Context, string) ([]string, error)
	cache   map[string][]string
	active  map[string]bool
	queries int
	terms   int
	issues  []string
}

func spfDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return "", fmt.Errorf("SPF needs a DNS domain, not an IP address")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid SPF domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("unsupported SPF domain or macro")
			}
		}
	}
	return s, nil
}

func (a *spfAudit) walk(domain string, depth int) (int, error) {
	if depth > 16 {
		return 0, fmt.Errorf("SPF recursion exceeds 16 levels")
	}
	domain, err := spfDomain(domain)
	if err != nil {
		return 0, err
	}
	if a.active[domain] {
		return 0, fmt.Errorf("SPF include/redirect cycle at %s", domain)
	}
	a.active[domain] = true
	defer delete(a.active, domain)
	records, ok := a.cache[domain]
	if !ok {
		if a.queries >= 32 {
			return 0, fmt.Errorf("SPF exceeds 32 TXT queries")
		}
		a.queries++
		txt, err := a.lookup(a.ctx, domain)
		if err != nil {
			return 0, fmt.Errorf("TXT %s: %w", domain, err)
		}
		for _, r := range txt {
			if len(r) > 8192 {
				return 0, fmt.Errorf("TXT record exceeds 8 KiB")
			}
			fields := strings.Fields(r)
			if len(fields) > 0 && strings.EqualFold(fields[0], "v=spf1") {
				records = append(records, r)
			}
		}
		a.cache[domain] = records
	}
	if len(records) != 1 {
		return 0, fmt.Errorf("%s: expected one SPF record, found %d", domain, len(records))
	}
	fields := strings.Fields(records[0])[1:]
	cost := 0
	redirect := ""
	for _, raw := range fields {
		a.terms++
		if a.terms > 256 {
			return 0, fmt.Errorf("SPF exceeds 256 terms")
		}
		term := raw
		qualified := len(term) > 0 && strings.ContainsAny(term[:1], "+-~?")
		if qualified {
			term = term[1:]
		}
		if strings.Contains(term, "=") {
			if qualified {
				return 0, fmt.Errorf("SPF modifier cannot have a qualifier")
			}
			key, value, _ := strings.Cut(term, "=")
			if strings.EqualFold(key, "redirect") {
				if value == "" {
					return 0, fmt.Errorf("empty SPF redirect")
				}
				if redirect != "" {
					return 0, fmt.Errorf("duplicate SPF redirect")
				}
				redirect = value
			}
			continue // exp and unknown modifiers do not count towards the limit.
		}
		name, arg, colon := strings.Cut(term, ":")
		name = strings.ToLower(strings.SplitN(name, "/", 2)[0])
		switch name {
		case "all":
			if !strings.EqualFold(term, "all") {
				return 0, fmt.Errorf("invalid SPF all")
			}
			if strings.EqualFold(raw, "all") || strings.EqualFold(raw, "+all") {
				a.issues = append(a.issues, domain+": +all permits every sender IP")
			}
			// Later mechanisms can never be reached. redirect is ignored with all.
			return cost, nil
		case "ip4", "ip6":
			if !colon {
				return 0, fmt.Errorf("missing SPF IP address")
			}
			ip := net.ParseIP(arg)
			if strings.Contains(arg, "/") {
				ip, _, err = net.ParseCIDR(arg)
			} else {
				err = nil
			}
			if err != nil || ip == nil || (name == "ip4" && ip.To4() == nil) || (name == "ip6" && ip.To4() != nil) {
				return 0, fmt.Errorf("invalid SPF %s", name)
			}
		case "include":
			if !colon {
				return 0, fmt.Errorf("missing SPF include domain")
			}
			cost++
			n, err := a.walk(arg, depth+1)
			if err != nil {
				return 0, err
			}
			cost += n
		case "a", "mx", "ptr", "exists":
			if name == "exists" && !colon {
				return 0, fmt.Errorf("missing SPF exists domain")
			}
			if strings.Contains(arg, "%") {
				return 0, fmt.Errorf("SPF macros need sender context")
			}
			cost++
			if name == "ptr" {
				a.issues = append(a.issues, domain+": PTR mechanism is discouraged")
			}
		default:
			return 0, fmt.Errorf("unsupported SPF mechanism %q", raw)
		}
	}
	if redirect != "" {
		cost++
		n, err := a.walk(redirect, depth+1)
		if err != nil {
			return 0, err
		}
		cost += n
	}
	return cost, nil
}

func auditSPF(ctx context.Context, domain string) (string, error) {
	domain, err := spfDomain(domain)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	a := spfAudit{ctx: ctx, lookup: net.DefaultResolver.LookupTXT, cache: map[string][]string{}, active: map[string]bool{}}
	cost, err := a.walk(domain, 0)
	// DNS failures, malformed policies, macros and missing records are explicitly
	// inconclusive, never a successful limit check or a clean security result.
	if err != nil {
		return "", err
	}
	out := fmt.Sprintf("SPF_AUDIT domain=%s dns_terms_upper_bound=%d txt_queries=%d\n", domain, cost, a.queries)
	if cost > 10 {
		out += "potential_lookup_limit_exceeded: upper bound > 10; actual evaluation depends on sender IP and short-circuiting\n"
	} else {
		out += "static DNS-term upper bound <= 10; not a full SPF authentication or void-lookup audit\n"
	}
	if len(a.issues) > 0 {
		out += strings.Join(a.issues, "\n") + "\n"
	}
	return out + "DNS includes/redirects followed through system resolver; no SMTP messages sent", nil
}
