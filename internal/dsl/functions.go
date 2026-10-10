package dsl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// --- value coercion ------------------------------------------------------

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != "" && x != "false"
	case nil:
		return false
	}
	return true
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toNumber(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err == nil {
			return f
		}
	}
	return 0
}

func isNumeric(v any) bool {
	switch x := v.(type) {
	case float64:
		return true
	case string:
		_, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return err == nil && x != ""
	}
	return false
}

// looseEqual compares two values; numbers compare numerically, everything else
// compares as strings, matching Nuclei's forgiving equality.
func looseEqual(a, b any) bool {
	if isNumeric(a) && isNumeric(b) {
		return toNumber(a) == toNumber(b)
	}
	if ab, ok := a.(bool); ok {
		return ab == truthy(b)
	}
	if bb, ok := b.(bool); ok {
		return bb == truthy(a)
	}
	return toString(a) == toString(b)
}

// --- function registry ---------------------------------------------------

type fn func(args []any) (any, error)

func need(args []any, n int, name string) error {
	if len(args) < n {
		return fmt.Errorf("%s expects at least %d arguments", name, n)
	}
	return nil
}

var functions = map[string]fn{
	"contains": func(a []any) (any, error) {
		if err := need(a, 2, "contains"); err != nil {
			return nil, err
		}
		return strings.Contains(toString(a[0]), toString(a[1])), nil
	},
	"icontains": func(a []any) (any, error) {
		if err := need(a, 2, "icontains"); err != nil {
			return nil, err
		}
		return strings.Contains(strings.ToLower(toString(a[0])), strings.ToLower(toString(a[1]))), nil
	},
	"contains_all": func(a []any) (any, error) {
		if err := need(a, 2, "contains_all"); err != nil {
			return nil, err
		}
		hay := toString(a[0])
		for _, needle := range a[1:] {
			if !strings.Contains(hay, toString(needle)) {
				return false, nil
			}
		}
		return true, nil
	},
	"contains_any": func(a []any) (any, error) {
		if err := need(a, 2, "contains_any"); err != nil {
			return nil, err
		}
		hay := toString(a[0])
		for _, needle := range a[1:] {
			if strings.Contains(hay, toString(needle)) {
				return true, nil
			}
		}
		return false, nil
	},
	"starts_with": func(a []any) (any, error) {
		if err := need(a, 2, "starts_with"); err != nil {
			return nil, err
		}
		s := toString(a[0])
		for _, p := range a[1:] {
			if strings.HasPrefix(s, toString(p)) {
				return true, nil
			}
		}
		return false, nil
	},
	"ends_with": func(a []any) (any, error) {
		if err := need(a, 2, "ends_with"); err != nil {
			return nil, err
		}
		s := toString(a[0])
		for _, p := range a[1:] {
			if strings.HasSuffix(s, toString(p)) {
				return true, nil
			}
		}
		return false, nil
	},
	"equals_any": func(a []any) (any, error) {
		if err := need(a, 2, "equals_any"); err != nil {
			return nil, err
		}
		for _, v := range a[1:] {
			if looseEqual(a[0], v) {
				return true, nil
			}
		}
		return false, nil
	},
	"regex": func(a []any) (any, error) {
		if err := need(a, 2, "regex"); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(toString(a[0]))
		if err != nil {
			return false, nil
		}
		return re.MatchString(toString(a[1])), nil
	},
	"len": func(a []any) (any, error) {
		if err := need(a, 1, "len"); err != nil {
			return nil, err
		}
		return float64(len(toString(a[0]))), nil
	},
	"to_lower": lowerFn, "tolower": lowerFn,
	"to_upper": upperFn, "toupper": upperFn,
	"trim": func(a []any) (any, error) {
		if err := need(a, 1, "trim"); err != nil {
			return nil, err
		}
		cut := " \t\r\n"
		if len(a) > 1 {
			cut = toString(a[1])
		}
		return strings.Trim(toString(a[0]), cut), nil
	},
	"trim_space": func(a []any) (any, error) {
		if err := need(a, 1, "trim_space"); err != nil {
			return nil, err
		}
		return strings.TrimSpace(toString(a[0])), nil
	},
	"concat": func(a []any) (any, error) {
		var b strings.Builder
		for _, v := range a {
			b.WriteString(toString(v))
		}
		return b.String(), nil
	},
	"replace": func(a []any) (any, error) {
		if err := need(a, 3, "replace"); err != nil {
			return nil, err
		}
		return strings.ReplaceAll(toString(a[0]), toString(a[1]), toString(a[2])), nil
	},
	"substr": substrFn, "substring": substrFn,
	"to_number": func(a []any) (any, error) {
		if err := need(a, 1, "to_number"); err != nil {
			return nil, err
		}
		return toNumber(a[0]), nil
	},
	"to_string": func(a []any) (any, error) {
		if err := need(a, 1, "to_string"); err != nil {
			return nil, err
		}
		return toString(a[0]), nil
	},
	"md5": func(a []any) (any, error) {
		if err := need(a, 1, "md5"); err != nil {
			return nil, err
		}
		sum := md5.Sum([]byte(toString(a[0])))
		return hex.EncodeToString(sum[:]), nil
	},
	"sha1": func(a []any) (any, error) {
		if err := need(a, 1, "sha1"); err != nil {
			return nil, err
		}
		sum := sha1.Sum([]byte(toString(a[0])))
		return hex.EncodeToString(sum[:]), nil
	},
	"sha256": func(a []any) (any, error) {
		if err := need(a, 1, "sha256"); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(toString(a[0])))
		return hex.EncodeToString(sum[:]), nil
	},
	"base64": func(a []any) (any, error) {
		if err := need(a, 1, "base64"); err != nil {
			return nil, err
		}
		return base64.StdEncoding.EncodeToString([]byte(toString(a[0]))), nil
	},
	"base64_decode": func(a []any) (any, error) {
		if err := need(a, 1, "base64_decode"); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(toString(a[0]))
		if err != nil {
			return "", nil
		}
		return string(b), nil
	},
	"hex_decode": func(a []any) (any, error) {
		if err := need(a, 1, "hex_decode"); err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(toString(a[0]))
		if err != nil {
			return "", nil
		}
		return string(b), nil
	},
	"hex_encode": func(a []any) (any, error) {
		if err := need(a, 1, "hex_encode"); err != nil {
			return nil, err
		}
		return hex.EncodeToString([]byte(toString(a[0]))), nil
	},
	"url_encode": func(a []any) (any, error) {
		if err := need(a, 1, "url_encode"); err != nil {
			return nil, err
		}
		return url.QueryEscape(toString(a[0])), nil
	},
	"url_decode": func(a []any) (any, error) {
		if err := need(a, 1, "url_decode"); err != nil {
			return nil, err
		}
		s, err := url.QueryUnescape(toString(a[0]))
		if err != nil {
			return "", nil
		}
		return s, nil
	},
	"compare_versions": func(a []any) (any, error) {
		if err := need(a, 2, "compare_versions"); err != nil {
			return nil, err
		}
		version := strings.TrimSpace(toString(a[0]))
		// An empty or non-numeric version (e.g. the version extractor did not
		// match) must not satisfy a constraint: otherwise it compares as "0" and
		// "< X" is spuriously true, fabricating a version-based finding.
		if version == "" || !strings.ContainsAny(version, "0123456789") {
			return false, nil
		}
		for _, c := range a[1:] {
			ok, err := versionConstraint(version, toString(c))
			if err != nil {
				return false, nil
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	},
}

func lowerFn(a []any) (any, error) {
	if err := need(a, 1, "to_lower"); err != nil {
		return nil, err
	}
	return strings.ToLower(toString(a[0])), nil
}

func upperFn(a []any) (any, error) {
	if err := need(a, 1, "to_upper"); err != nil {
		return nil, err
	}
	return strings.ToUpper(toString(a[0])), nil
}

func substrFn(a []any) (any, error) {
	if err := need(a, 2, "substr"); err != nil {
		return nil, err
	}
	s := toString(a[0])
	start := int(toNumber(a[1]))
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return "", nil
	}
	end := len(s)
	if len(a) > 2 {
		end = start + int(toNumber(a[2]))
	}
	if end > len(s) {
		end = len(s)
	}
	if end < start {
		end = start
	}
	return s[start:end], nil
}

// versionConstraint reports whether version satisfies a single constraint such
// as ">=1.2.3", "<2.0", "=1.0" or a bare "1.0" (treated as equality). It is a
// lightweight numeric-segment comparison, not a full semver implementation.
func versionConstraint(version, constraint string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	op := "="
	for _, candidate := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
		if strings.HasPrefix(constraint, candidate) {
			op = candidate
			constraint = strings.TrimSpace(constraint[len(candidate):])
			break
		}
	}
	cmp := compareVersions(version, constraint)
	switch op {
	case ">":
		return cmp > 0, nil
	case ">=":
		return cmp >= 0, nil
	case "<":
		return cmp < 0, nil
	case "<=":
		return cmp <= 0, nil
	case "!=":
		return cmp != 0, nil
	default:
		return cmp == 0, nil
	}
}

// compareVersions returns -1, 0 or 1 comparing two dotted version strings by
// numeric segments, ignoring a leading "v" and any non-numeric suffix.
func compareVersions(a, b string) int {
	as := versionSegments(a)
	bs := versionSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionSegments(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out []int
	for _, part := range strings.Split(v, ".") {
		num := 0
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				break
			}
			num = num*10 + int(part[i]-'0')
		}
		out = append(out, num)
	}
	return out
}
