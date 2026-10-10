package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

const jsScriptTimeout = 60 * time.Second

// execJavaScript runs one javascript: request block (optionally expanded by
// payloads/attack) against target using the embedded goja runtime and
// nuclei-compatible require("nuclei/…") helpers. lastResponse is the final
// script's response (set regardless of match, like execHTTPRequest's snap)
// — a flow: script's javascript() needs it to populate
// {{javascript_response}} (see execFlow).
func execJavaScript(ctx context.Context, t domain.Template, req domain.JavaScriptRequest, target string, vars map[string]any, tvars map[string]string, libraryDir string, timeout time.Duration) (findings []domain.Finding, errs []error, lastResponse string) {
	if strings.TrimSpace(req.Code) == "" {
		// Some templates split pre-condition into its own list item; skip no-ops.
		return nil, nil, ""
	}
	if timeout <= 0 {
		timeout = jsScriptTimeout
	}

	effectivePayloads := req.Payloads
	if strings.TrimSpace(req.Init) != "" {
		initArgs := renderJSArgs(req.Args, vars, tvars)
		if _, ok := initArgs["Host"]; !ok {
			initArgs["Host"] = tvars["Host"]
		}
		if _, ok := initArgs["Port"]; !ok {
			initArgs["Port"] = tvars["Port"]
		}
		initArgs["Host"], initArgs["Port"] = tvars["Host"], tvars["Port"]
		initCode := applyTargetVars(render(req.Init, vars), tvars)
		initResult := js.RunInit(ctx, initCode, initArgs, libraryDir, timeout)
		if initResult.Error != "" {
			errs = append(errs, fmt.Errorf("%s: javascript init: %s", t.ID, initResult.Error))
		} else {
			if len(initResult.Payloads) > 0 {
				merged := make(domain.PayloadSet, len(effectivePayloads)+len(initResult.Payloads))
				for k, v := range effectivePayloads {
					merged[k] = v
				}
				for name, raw := range initResult.Payloads {
					merged[name] = jsValueToPayload(raw)
				}
				effectivePayloads = merged
			}
			if len(initResult.Args) > 0 {
				vars = mergeVars(vars, initResult.Args)
			}
		}
	}

	combos, prepErrs := jsPayloadCombos(domain.JavaScriptRequest{Payloads: effectivePayloads, Attack: req.Attack}, vars, tvars, libraryDir, t.Source)
	errs = append(errs, prepErrs...)

	for _, combo := range combos {
		if ctx.Err() != nil {
			return findings, errs, lastResponse
		}
		env := vars
		if len(combo) > 0 {
			env = make(map[string]any, len(vars)+len(combo))
			for k, v := range vars {
				env[k] = v
			}
			for k, v := range combo {
				env[k] = v
			}
		}
		args := renderJSArgs(req.Args, env, tvars)
		// Ensure Host/Port from the scan target when the template omits them.
		if _, ok := args["Host"]; !ok {
			args["Host"] = tvars["Host"]
		}
		if _, ok := args["Port"]; !ok {
			args["Port"] = tvars["Port"]
		}
		// Always bind the JS request to the explicitly selected service.
		args["Host"] = tvars["Host"]
		args["Port"] = tvars["Port"]
		// "Port: 80,443" (comma list, nuclei's "try more than one port"
		// shorthand — e.g. CVE-2018-8011.yaml, CVE-2024-23897.yaml) isn't a
		// real port: passed straight through, Go's dialer reads it as a
		// service name and fails with "unknown port". We don't run the
		// request once per port like nuclei's getPorts() does (only two
		// templates in the library use this, not worth a second attack-style
		// iteration axis) — take the first port, which is enough for the
		// scripts observed (they just need one reachable port, trying
		// TLS-then-plain themselves, not branching on which port it got).
		if port, ok := args["Port"].(string); ok {
			if i := strings.IndexByte(port, ','); i >= 0 {
				args["Port"] = strings.TrimSpace(port[:i])
			}
		}

		pre := applyTargetVars(render(req.PreCondition, env), tvars)
		code := applyTargetVars(render(req.Code, env), tvars)
		// Upstream catches every failure and retries 1001 times, including dead
		// endpoints. Keep its wrong-password test but retry only auth rejection.
		if t.ID == "CVE-2012-2122" {
			code = `var m = require("nuclei/mysql");
 var c = m.MySQLClient();
 var r = c.CheckAuthenticationBypass(Host, Port, User, Pass, Query);
 if (r.Vulnerable) { Export(r.Result); } else { false; }`
		}
		result := js.Run(ctx, code, pre, args, env, libraryDir, timeout)

		responseStr := jsResponseString(result.Response)
		lastResponse = responseStr
		matchEnv := map[string]any{
			"response": responseStr,
			"success":  result.Success,
		}
		if result.Error != "" {
			matchEnv["error"] = result.Error
		}
		for k, v := range result.Exports {
			matchEnv[k] = v
		}
		for k, v := range env {
			if _, ok := matchEnv[k]; !ok {
				matchEnv[k] = v
			}
		}
		// DSL often compares response == true for boolean returns.
		if b, ok := result.Response.(bool); ok {
			matchEnv["response"] = b
		}

		extra := runExtractors(req.Extractors, matchEnv, nil, nil, []byte(responseStr))
		matched, evidence := matchOrExtract(req.Matchers, req.MatchersCondition, 0, nil, []byte(responseStr), matchEnv, extra)
		if matched && extra == "" {
			// Without an extractor, "dsl matched: ..." names the condition
			// but not what the script actually found — for a javascript:
			// template the script's own response (often a small struct like
			// rdp-detect.yaml's {"IsRDP": true, "OS": "..."}) IS the finding,
			// so fold a short rendering of it into the evidence shown by
			// default instead of leaving it visible only behind "r" (raw).
			if s := jsEvidenceSummary(responseStr); s != "" {
				if evidence != "" {
					evidence += "; "
				}
				evidence += s
			}
		}
		if matched {
			// Credential-testing templates (the javascript/default-logins/
			// family — smb-default-login.yaml, mysql-default-login.yaml,
			// ldap-default-login.yaml, … — plus any other template using the
			// same args: User/Pass convention) attack: clusterbomb over a
			// payload list and stop-at-first-match on the winning combo. The
			// script's own response (e.g. a share list) says nothing about
			// WHICH credential pair actually worked, which for this class of
			// finding is the entire point — without it the finding reads as
			// "found something" with no way to tell why. args here is
			// already the per-iteration rendered combo (post-render(), the
			// same map just passed to js.Run), not the raw {{payload}}
			// placeholder.
			if user, ok := args["User"]; ok {
				cred := fmt.Sprintf("user=%q", fmt.Sprint(user))
				if pass, ok := args["Pass"]; ok {
					cred += fmt.Sprintf(" pass=%q", fmt.Sprint(pass))
				}
				if evidence != "" {
					evidence += "; "
				}
				evidence += cred
			}
		}
		if result.Error != "" && !matched && !isBenignJavaScriptError(result.Error) {
			errs = append(errs, fmt.Errorf("%s: javascript: %s", t.ID, result.Error))
		}
		if !matched {
			continue
		}
		if matchersOnlyInternal(req.Matchers) {
			continue
		}
		findings = append(findings, domain.Finding{
			TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
			Target: target, MatchedAt: "javascript://" + tvars["Hostname"],
			Evidence: evidence, Risk: t.Risk, Protocol: "javascript",
			Response: responseStr, Time: time.Now().UTC(),
		})
		if req.StopAtFirstMatch {
			return findings, errs, lastResponse
		}
	}
	return findings, errs, lastResponse
}

// benignJavaScriptErrorPatterns are uncaught javascript: errors that mean
// "this probe found nothing interesting" — not a client bug, a genuine
// network problem, or a protocol-handling defect. Matching here demotes
// exactly these known-benign outcomes to a quiet non-match; anything else —
// a real crash, a timeout, an actual client/library defect — still surfaces
// as an error exactly as before. Two families:
//
//   - Credential rejection: credential-guessing templates
//     (ssh-default-logins.yaml, CVE-2023-34039.yaml, …) throw on every wrong
//     guess because they don't wrap the attempt in try/catch (same as real
//     nuclei — this isn't a gap specific to our engine), so a 223-entry
//     wordlist produces up to 223 "check errors" for a single,
//     not-vulnerable host. Each pattern is the literal server/library
//     wording for "wrong credentials", not a guess:
//     ssh (zgrab2/lib/ssh, same wording as golang.org/x/crypto/ssh):
//     "ssh: unable to authenticate, attempted methods [...], no supported
//     methods remain"; smb/ntlm (go-smb2): the Windows NTSTATUS message
//     text for STATUS_LOGON_FAILURE; mysql: the MySQL server's own
//     ER_ACCESS_DENIED_ERROR text, relayed verbatim by go-sql-driver/mysql;
//     postgres: the PostgreSQL server's own message for a failed
//     MD5/SCRAM login, relayed verbatim by lib/pq.
var benignJavaScriptErrorPatterns = []string{
	"noauth authentication required",
	"wrongpass invalid username-password",
	"err invalid password",
	"err auth <password> called without any password configured",
	"unable to authenticate",         // ssh: wrong password/key, no auth method worked
	"the attempted logon is invalid", // smb/ntlm: STATUS_LOGON_FAILURE
	"access denied for user",         // mysql: wrong credentials
	"password authentication failed", // postgres: wrong credentials
}

func isBenignJavaScriptError(errMsg string) bool {
	lower := strings.ToLower(errMsg)
	for _, p := range benignJavaScriptErrorPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return isBenignUDPRefusal(lower) || isBenignUndefinedPropertyAccess(errMsg)
}

// isBenignUndefinedPropertyAccess matches goja's own fixed wording for a
// TypeError on a null/undefined property access — "Cannot read property 'x'
// of undefined[ or null]" — reproducing "CVE-2022-24637: TypeError: Cannot
// read property '1' of undefined". The script chains an earlier step's
// internal extractor straight into a method call with no null guard
// (`serobj.substring(...).match(/.../)[1]`): when the target isn't the
// vulnerable app, the extractor finds nothing, match() returns null, and the
// very next line throws. Real nuclei runs on the same goja engine and hits
// the identical TypeError in the identical situation — on a non-vulnerable
// target this is nuclei's own "not vulnerable, stop" signal, not a defect in
// our engine (same reasoning as flow.go's isBenignFlowChainBreak, which
// covers the same pattern one level up, inside a flow: script rather than a
// javascript: block).
func isBenignUndefinedPropertyAccess(errMsg string) bool {
	return strings.Contains(errMsg, "Cannot read property") &&
		(strings.Contains(errMsg, "of undefined") || strings.Contains(errMsg, "of null"))
}

// isBenignUDPRefusal matches a UDP ICMP port-unreachable surfacing as a Go
// net error (tftp-detect.yaml and similar: "read udp 1.2.3.4:5678->
// 1.2.3.4:69: read: connection refused"). isUDPPortOpen can't actually
// verify a UDP port is listening — a UDP dial always "succeeds" since
// there's no handshake — so the precondition passes regardless and the
// refusal only surfaces later, on the first Recv. That's the UDP equivalent
// of a closed TCP port (see discovery/ports.go's discoveryOverload, which
// treats it the same way for port scanning), never a bug on our side.
//
// Matched narrowly on net.OpError's own "<op> udp ...: connection refused"
// wording (the literal word "udp" must appear) rather than a blanket
// "connection refused" — a TCP connection refused reaching this point means
// the template ran past its isPortOpen precondition against a closed port,
// which is exactly the real-problem case
// TestSSHDefaultLoginsConnectionRefusedStillErrors guards against staying
// visible.
func isBenignUDPRefusal(lowerErrMsg string) bool {
	return strings.Contains(lowerErrMsg, "udp") && strings.Contains(lowerErrMsg, "connection refused")
}

// jsEvidenceSummary collapses a javascript: response into a one-line
// evidence excerpt (whitespace/newlines folded, capped so a large banner
// dump doesn't blow up the finding list) — the full, unflattened response is
// still always available in Finding.Response (the "r" raw view).
func jsEvidenceSummary(response string) string {
	s := strings.Join(strings.Fields(response), " ")
	const maxLen = 300
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}

func jsResponseString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case bool, int, int64, float64:
		return fmt.Sprint(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
}

func renderJSArgs(args map[string]any, env map[string]any, tvars map[string]string) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		switch x := v.(type) {
		case string:
			out[k] = applyTargetVars(render(x, env), tvars)
		case int, int64, bool:
			out[k] = x
		case float64:
			if x == float64(int(x)) {
				out[k] = int(x)
			} else {
				out[k] = x
			}
		default:
			out[k] = applyTargetVars(render(fmt.Sprint(x), env), tvars)
		}
	}
	return out
}

// jsValueToPayload converts an init: script's updatePayload(name, value)
// argument (goja-exported — typically []any of strings, or a bare string)
// into a domain.Payload, the shape jsPayloadCombos/payloadCombos expect.
func jsValueToPayload(raw any) domain.Payload {
	switch v := raw.(type) {
	case []any:
		values := make([]string, 0, len(v))
		for _, item := range v {
			values = append(values, fmt.Sprint(item))
		}
		return domain.Payload{Values: values}
	case []string:
		return domain.Payload{Values: v}
	case string:
		return domain.Payload{Values: []string{v}}
	default:
		return domain.Payload{Values: []string{fmt.Sprint(v)}}
	}
}

// mergeVars overlays overrides (from an init: script's set() calls) onto a
// copy of vars, leaving the original map (shared with other combos/targets)
// untouched.
func mergeVars(vars map[string]any, overrides map[string]any) map[string]any {
	out := make(map[string]any, len(vars)+len(overrides))
	for k, v := range vars {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// jsPayloadCombos mirrors payloadCombos for javascript: blocks (same attack
// modes, shared file-payload resolution).
func jsPayloadCombos(r domain.JavaScriptRequest, vars map[string]any, tvars map[string]string, libraryDir, source string) ([]map[string]string, []error) {
	if len(r.Payloads) == 0 {
		return []map[string]string{{}}, nil
	}
	// Reuse HTTP payload machinery by projecting into a throwaway HTTPRequest.
	return payloadCombos(domain.HTTPRequest{Payloads: r.Payloads, Attack: r.Attack}, vars, tvars, libraryDir, source)
}
