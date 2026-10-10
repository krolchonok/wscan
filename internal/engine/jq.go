package engine

import (
	"strconv"
	"strings"
)

// jqEval is a small jq-subset evaluator for JSON extractors. It supports the
// forms nuclei templates commonly use: key access (`.a.b`), optional keys
// (`.a?`), array iteration (`.arr[]`), and `select(.k == "v")` / `!=` filters,
// composed through the `|` pipe. Anything it cannot parse yields no values.
func jqEval(doc any, path string) []string {
	cur := []any{doc}
	for _, stage := range strings.Split(path, "|") {
		cur = jqStage(cur, strings.TrimSpace(stage))
	}
	out := make([]string, 0, len(cur))
	for _, v := range cur {
		if v == nil {
			continue
		}
		out = append(out, jqToString(v))
	}
	return out
}

func jqStage(set []any, stage string) []any {
	for i := 0; i < len(stage); {
		switch {
		case strings.HasPrefix(stage[i:], "select("):
			end := strings.IndexByte(stage[i:], ')')
			if end < 0 {
				return set
			}
			set = jqSelect(set, stage[i+7:i+end])
			i += end + 1
		case stage[i] == '.':
			j := i + 1
			for j < len(stage) && isIdentByte(stage[j]) {
				j++
			}
			if key := stage[i+1 : j]; key != "" {
				set = jqKey(set, key)
			}
			i = j
		case strings.HasPrefix(stage[i:], "[]"):
			set = jqIter(set)
			i += 2
		default:
			i++ // skip '?', whitespace and unsupported syntax
		}
	}
	return set
}

func jqKey(set []any, key string) []any {
	var out []any
	for _, v := range set {
		if m, ok := v.(map[string]any); ok {
			if val, ok := m[key]; ok {
				out = append(out, val)
			}
		}
	}
	return out
}

func jqIter(set []any) []any {
	var out []any
	for _, v := range set {
		if arr, ok := v.([]any); ok {
			out = append(out, arr...)
		}
	}
	return out
}

// jqSelect keeps objects in set for which `cond` (e.g. `.k == "v"`) holds.
func jqSelect(set []any, cond string) []any {
	cond = strings.TrimSpace(cond)
	op := ""
	for _, candidate := range []string{"==", "!="} {
		if idx := strings.Index(cond, candidate); idx >= 0 {
			op = candidate
			leftPath := strings.TrimSpace(cond[:idx])
			want := strings.Trim(strings.TrimSpace(cond[idx+2:]), `"'`)
			var out []any
			for _, v := range set {
				got := ""
				if vals := jqEval(v, leftPath); len(vals) > 0 {
					got = vals[0]
				}
				if (op == "==" && got == want) || (op == "!=" && got != want) {
					out = append(out, v)
				}
			}
			return out
		}
	}
	return set
}

func jqToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func isIdentByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}
