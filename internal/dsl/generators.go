package dsl

import (
	"math/rand"
	"strings"
	"time"
)

// Generator helpers mirror the nuclei template functions commonly used by
// variables and raw requests (rand_base, rand_text_*, rand_int, rand_char).
// Randomness is for payload uniqueness, not security, so math/rand is fine.

const (
	alphaChars   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numericChars = "0123456789"
	alnumChars   = alphaChars + numericChars
)

func init() {
	functions["rand_base"] = func(a []any) (any, error) {
		if err := need(a, 1, "rand_base"); err != nil {
			return nil, err
		}
		charset := alnumChars
		if len(a) > 1 && toString(a[1]) != "" {
			charset = toString(a[1])
		}
		return randString(int(toNumber(a[0])), charset), nil
	}
	functions["rand_text_alpha"] = randTextFn("rand_text_alpha", alphaChars)
	functions["rand_text_alphanumeric"] = randTextFn("rand_text_alphanumeric", alnumChars)
	functions["rand_text_numeric"] = randTextFn("rand_text_numeric", numericChars)
	functions["rand_char"] = func(a []any) (any, error) {
		charset := alnumChars
		if len(a) > 0 && toString(a[0]) != "" {
			charset = toString(a[0])
		}
		return randString(1, charset), nil
	}
	functions["date_time"] = func(a []any) (any, error) {
		if err := need(a, 1, "date_time"); err != nil {
			return nil, err
		}
		t := time.Now()
		if len(a) > 1 {
			if sec := int64(toNumber(a[1])); sec > 0 {
				t = time.Unix(sec, 0)
			}
		}
		return t.Format(strftimeToGo(toString(a[0]))), nil
	}
	functions["unix_time"] = func(a []any) (any, error) {
		return float64(time.Now().Unix()), nil
	}
	functions["to_unix_time"] = functions["unix_time"]
	functions["rand_int"] = func(a []any) (any, error) {
		lo, hi := 0, 2147483647
		if len(a) > 0 {
			lo = int(toNumber(a[0]))
		}
		if len(a) > 1 {
			hi = int(toNumber(a[1]))
		}
		if hi <= lo {
			return float64(lo), nil
		}
		return float64(lo + rand.Intn(hi-lo+1)), nil
	}
}

// randTextFn builds a rand_text_* function; the optional second argument lists
// characters to exclude from the charset.
func randTextFn(name, charset string) fn {
	return func(a []any) (any, error) {
		if err := need(a, 1, name); err != nil {
			return nil, err
		}
		cs := charset
		if len(a) > 1 && toString(a[1]) != "" {
			cs = removeChars(cs, toString(a[1]))
		}
		return randString(int(toNumber(a[0])), cs), nil
	}
}

func randString(n int, charset string) string {
	if n <= 0 || charset == "" {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func removeChars(charset, bad string) string {
	out := make([]byte, 0, len(charset))
	for i := 0; i < len(charset); i++ {
		if !containsByte(bad, charset[i]) {
			out = append(out, charset[i])
		}
	}
	if len(out) == 0 {
		return charset
	}
	return string(out)
}

// strftimeToGo converts the common C strftime specifiers nuclei templates use
// into a Go reference-time layout.
func strftimeToGo(f string) string {
	r := strings.NewReplacer(
		"%Y", "2006", "%y", "06", "%m", "01", "%d", "02",
		"%H", "15", "%M", "04", "%S", "05", "%p", "PM",
		"%b", "Jan", "%B", "January", "%a", "Mon", "%A", "Monday",
	)
	return r.Replace(f)
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
