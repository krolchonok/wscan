package nse

import (
	"regexp"
	"strings"
	"unicode"
)

var envAssignRE = regexp.MustCompile(`(?m)^((?:local\s+)?_ENV\s*=\s*.+)$`)

// transformLua53 adapts Nmap nselib (Lua 5.3) for gopher-lua (Lua 5.1):
//  1. inject setfenv(1, _ENV) after module environment assignment
//  2. expand \z string escapes (Lua 5.2+)
//  3. rewrite bitwise / floor-div operators to bit.* calls
func transformLua53(src string) string {
	src = envAssignRE.ReplaceAllString(src, "$1; setfenv(1, _ENV)")
	toks := tokenizeLua(src)
	for i := range toks {
		if toks[i].kind == "str" {
			toks[i].val = normalizeLua53String(toks[i].val)
		}
	}
	if !hasBitop(toks) {
		return joinToks(toks)
	}
	return rewriteBitopsToks(toks)
}

func normalizeLua53String(s string) string {
	if len(s) < 2 {
		return s
	}
	// Keep long-bracket strings as-is.
	if s[0] == '[' {
		return s
	}
	q := s[0]
	body := s[1 : len(s)-1]
	var b strings.Builder
	b.Grow(len(body) + 8)
	for i := 0; i < len(body); {
		if body[i] != '\\' || i+1 >= len(body) {
			b.WriteByte(body[i])
			i++
			continue
		}
		next := body[i+1]
		// Lua 5.2+ \z skips following whitespace.
		if next == 'z' {
			i += 2
			for i < len(body) {
				switch body[i] {
				case ' ', '\t', '\n', '\r', '\f', '\v':
					i++
					continue
				}
				break
			}
			continue
		}
		// Lua 5.2+ \xHH → Lua 5.1 decimal escape \ddd
		if next == 'x' && i+3 < len(body) && isHexDigit(body[i+2]) && isHexDigit(body[i+3]) {
			v := unhex(body[i+2])<<4 | unhex(body[i+3])
			b.WriteByte('\\')
			// Always write 3 decimal digits so following digits aren't absorbed.
			b.WriteByte('0' + v/100)
			b.WriteByte('0' + (v/10)%10)
			b.WriteByte('0' + v%10)
			i += 4
			continue
		}
		b.WriteByte(body[i])
		b.WriteByte(next)
		i += 2
	}
	return string(q) + b.String() + string(q)
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func rewriteBitops(src string) string {
	return rewriteBitopsToks(tokenizeLua(src))
}

func rewriteBitopsToks(toks []tok) string {
	if !hasBitop(toks) {
		return joinToks(toks)
	}
	toks = rewriteBinaryOps(toks, []string{"//"}, "bit.idiv")
	toks = rewriteBinaryOps(toks, []string{"<<"}, "bit.lshift")
	toks = rewriteBinaryOps(toks, []string{">>"}, "bit.rshift")
	toks = rewriteUnaryNot(toks)
	toks = rewriteBinaryOps(toks, []string{"&"}, "bit.band")
	toks = rewriteBinaryOps(toks, []string{"~"}, "bit.bxor")
	toks = rewriteBinaryOps(toks, []string{"|"}, "bit.bor")
	return joinToks(toks)
}

type tok struct {
	kind string // space, str, ident, num, op, other
	val  string
}

func tokenizeLua(src string) []tok {
	var out []tok
	i := 0
	for i < len(src) {
		c := src[i]
		// comments
		if c == '-' && i+1 < len(src) && src[i+1] == '-' {
			if i+3 < len(src) && src[i+2] == '[' {
				// long comment --[=*[ ... ]=*]
				eq := 0
				j := i + 3
				for j < len(src) && src[j] == '=' {
					eq++
					j++
				}
				if j < len(src) && src[j] == '[' {
					j++
					close := "]" + strings.Repeat("=", eq) + "]"
					k := strings.Index(src[j:], close)
					if k < 0 {
						out = append(out, tok{"space", src[i:]})
						break
					}
					j += k + len(close)
					out = append(out, tok{"space", src[i:j]})
					i = j
					continue
				}
			}
			j := i
			for j < len(src) && src[j] != '\n' {
				j++
			}
			out = append(out, tok{"space", src[i:j]})
			i = j
			continue
		}
		// long string [=*[ ... ]=*]
		if c == '[' {
			eq := 0
			j := i + 1
			for j < len(src) && src[j] == '=' {
				eq++
				j++
			}
			if j < len(src) && src[j] == '[' {
				j++
				close := "]" + strings.Repeat("=", eq) + "]"
				k := strings.Index(src[j:], close)
				if k < 0 {
					out = append(out, tok{"str", src[i:]})
					break
				}
				j += k + len(close)
				out = append(out, tok{"str", src[i:j]})
				i = j
				continue
			}
		}
		// short string
		if c == '"' || c == '\'' {
			j := i + 1
			for j < len(src) {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == c {
					j++
					break
				}
				j++
			}
			out = append(out, tok{"str", src[i:j]})
			i = j
			continue
		}
		if unicode.IsSpace(rune(c)) {
			j := i
			for j < len(src) && unicode.IsSpace(rune(src[j])) {
				j++
			}
			out = append(out, tok{"space", src[i:j]})
			i = j
			continue
		}
		if unicode.IsLetter(rune(c)) || c == '_' {
			j := i
			for j < len(src) && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_') {
				j++
			}
			out = append(out, tok{"ident", src[i:j]})
			i = j
			continue
		}
		if unicode.IsDigit(rune(c)) || (c == '.' && i+1 < len(src) && unicode.IsDigit(rune(src[i+1]))) {
			j := i
			if strings.HasPrefix(strings.ToLower(src[j:]), "0x") {
				j += 2
				for j < len(src) && isHex(src[j]) {
					j++
				}
			} else {
				for j < len(src) && (unicode.IsDigit(rune(src[j])) || src[j] == '.' || src[j] == 'e' || src[j] == 'E' ||
					((src[j] == '+' || src[j] == '-') && j > i && (src[j-1] == 'e' || src[j-1] == 'E'))) {
					j++
				}
			}
			out = append(out, tok{"num", src[i:j]})
			i = j
			continue
		}
		two, three := "", ""
		if i+1 < len(src) {
			two = src[i : i+2]
		}
		if i+2 < len(src) {
			three = src[i : i+3]
		}
		switch {
		case three == "...":
			out = append(out, tok{"op", three})
			i += 3
		case two == "<<", two == ">>", two == "//", two == "~=", two == "==", two == "<=", two == ">=", two == "..", two == "::":
			out = append(out, tok{"op", two})
			i += 2
		default:
			out = append(out, tok{"op", string(c)})
			i++
		}
	}
	return out
}

func isHex(c byte) bool {
	return unicode.IsDigit(rune(c)) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func joinToks(toks []tok) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(t.val)
	}
	return b.String()
}

func isSpaceTok(t tok) bool { return t.kind == "space" }

func skipSpace(toks []tok, i int, dir int) int {
	for i >= 0 && i < len(toks) && isSpaceTok(toks[i]) {
		i += dir
	}
	return i
}

func hasBitop(toks []tok) bool {
	for _, t := range toks {
		if t.kind != "op" {
			continue
		}
		switch t.val {
		case "&", "|", "<<", ">>", "//":
			return true
		case "~":
			return true
		}
	}
	return false
}

func rewriteUnaryNot(toks []tok) []tok {
	for i := 0; i < len(toks); i++ {
		if toks[i].kind != "op" || toks[i].val != "~" {
			continue
		}
		// binary ~ has a left operand; unary does not
		left := skipSpace(toks, i-1, -1)
		if left >= 0 && isExprEnd(toks[left]) {
			continue
		}
		rightStart := skipSpace(toks, i+1, 1)
		if rightStart >= len(toks) {
			continue
		}
		rightEnd := takeOperandRight(toks, rightStart)
		var out []tok
		out = append(out, toks[:i]...)
		out = append(out, tok{"ident", "bit"}, tok{"op", "."}, tok{"ident", "bnot"}, tok{"op", "("})
		out = append(out, toks[rightStart:rightEnd+1]...)
		out = append(out, tok{"op", ")"})
		out = append(out, toks[rightEnd+1:]...)
		toks = out
		// continue from after inserted call
		i += 4
	}
	return toks
}

func rewriteBinaryOps(toks []tok, ops []string, fn string) []tok {
	opSet := map[string]bool{}
	for _, o := range ops {
		opSet[o] = true
	}
	for i := 0; i < len(toks); i++ {
		if toks[i].kind != "op" || !opSet[toks[i].val] {
			continue
		}
		leftEnd := skipSpace(toks, i-1, -1)
		if leftEnd < 0 {
			continue
		}
		leftStart := takeOperandLeft(toks, leftEnd)
		rightStart := skipSpace(toks, i+1, 1)
		if rightStart >= len(toks) {
			continue
		}
		rightEnd := takeOperandRight(toks, rightStart)
		parts := strings.Split(fn, ".")
		var call []tok
		call = append(call, tok{"ident", parts[0]}, tok{"op", "."}, tok{"ident", parts[1]}, tok{"op", "("})
		call = append(call, toks[leftStart:leftEnd+1]...)
		call = append(call, tok{"op", ","}, tok{"space", " "})
		call = append(call, toks[rightStart:rightEnd+1]...)
		call = append(call, tok{"op", ")"})
		var out []tok
		out = append(out, toks[:leftStart]...)
		out = append(out, call...)
		out = append(out, toks[rightEnd+1:]...)
		toks = out
		i = leftStart + len(call) - 1
	}
	return toks
}

func isExprEnd(t tok) bool {
	if t.kind == "ident" || t.kind == "num" || t.kind == "str" {
		return true
	}
	if t.kind == "op" {
		switch t.val {
		case ")", "]", "}", "...":
			return true
		}
	}
	return false
}

// luaKeywords are reserved words — never a function/table name, so a
// preceding `(expr)` is a grouped sub-expression, not a call's argument
// list. Missing this check was the bug behind ftp-syst.nse's "near 'bit'"
// syntax error: `... or (code % 100) // 10 == 3` has `or` right before
// `(code % 100)`, and takeOperandLeft treated `or` as if it were a function
// name being called with that parenthesized group as its arguments —
// producing `or(code % 100)` as the left side of the generated bit.idiv(…)
// call, which doesn't parse.
var luaKeywords = map[string]bool{
	"and": true, "break": true, "do": true, "else": true, "elseif": true,
	"end": true, "false": true, "for": true, "function": true, "goto": true,
	"if": true, "in": true, "local": true, "nil": true, "not": true,
	"or": true, "repeat": true, "return": true, "then": true, "true": true,
	"until": true, "while": true,
}

func isLuaKeyword(s string) bool { return luaKeywords[s] }

func takeOperandLeft(toks []tok, end int) int {
	i := skipSpace(toks, end, -1)
	if i < 0 {
		return 0
	}
	// Consume one primary from the right.
	if toks[i].kind == "op" && (toks[i].val == ")" || toks[i].val == "]" || toks[i].val == "}") {
		i = matchOpen(toks, i)
	} else if toks[i].kind != "ident" && toks[i].kind != "num" && toks[i].kind != "str" {
		return i
	}
	// Walk left through the whole postfix chain — name(...)[...].b:c(...)
	// etc. — one link at a time: a.b / a:b needs the dot, but a direct
	// index/call (`exports["(default)"]`, `foo()()`) attaches straight to
	// the preceding name/bracket with no dot at all, so both forms have to
	// be checked at every step, not just once at the chain's outermost link
	// (reproduces nbd-info.nse's "syntax error near '['": the old code only
	// absorbed a dotless index/call on the very first hop, so
	// `comm.exports["(default)"].hflags` left "comm.exports" behind as
	// plain text outside the bit.band(...) rewrite it chained into).
	for {
		j := skipSpace(toks, i-1, -1)
		if j < 0 {
			return i
		}
		if toks[j].kind == "op" && (toks[j].val == "." || toks[j].val == ":") {
			k := skipSpace(toks, j-1, -1)
			if k < 0 {
				return i
			}
			if toks[k].kind == "ident" || toks[k].kind == "num" || toks[k].kind == "str" {
				i = k
				continue
			}
			if toks[k].kind == "op" && (toks[k].val == ")" || toks[k].val == "]" || toks[k].val == "}") {
				i = matchOpen(toks, k)
				continue
			}
			return i
		}
		if toks[j].kind == "op" && (toks[j].val == ")" || toks[j].val == "]") {
			i = matchOpen(toks, j)
			continue
		}
		if toks[j].kind == "str" || toks[j].kind == "num" || (toks[j].kind == "ident" && !isLuaKeyword(toks[j].val)) {
			i = j
			continue
		}
		return i
	}
}

func takeOperandRight(toks []tok, start int) int {
	i := start
	for i < len(toks) {
		i = skipSpace(toks, i, 1)
		if i >= len(toks) {
			return len(toks) - 1
		}
		t := toks[i]
		if t.kind == "op" && (t.val == "(" || t.val == "[" || t.val == "{") {
			i = matchClose(toks, i)
			// continue to allow a()[1].x
			j := skipSpace(toks, i+1, 1)
			if j < len(toks) && toks[j].kind == "op" && (toks[j].val == "(" || toks[j].val == "[" || toks[j].val == "." || toks[j].val == ":") {
				i = j
				continue
			}
			return i
		}
		if t.kind == "ident" || t.kind == "num" || t.kind == "str" {
			for {
				j := skipSpace(toks, i+1, 1)
				if j >= len(toks) {
					return i
				}
				if toks[j].kind == "op" && (toks[j].val == "." || toks[j].val == ":") {
					k := skipSpace(toks, j+1, 1)
					if k < len(toks) && toks[k].kind == "ident" {
						i = k
						continue
					}
				}
				if toks[j].kind == "op" && (toks[j].val == "(" || toks[j].val == "[") {
					i = matchClose(toks, j)
					continue
				}
				return i
			}
		}
		if t.kind == "op" && (t.val == "#" || t.val == "-" || t.val == "not" || t.val == "~") {
			// unary then operand
			rest := takeOperandRight(toks, skipSpace(toks, i+1, 1))
			return rest
		}
		return i
	}
	return start
}

func matchOpen(toks []tok, closeIdx int) int {
	close := toks[closeIdx].val
	open := map[string]string{")": "(", "]": "[", "}": "{"}[close]
	depth := 0
	for i := closeIdx; i >= 0; i-- {
		if toks[i].kind != "op" {
			continue
		}
		if toks[i].val == close {
			depth++
		} else if toks[i].val == open {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return 0
}

func matchClose(toks []tok, openIdx int) int {
	open := toks[openIdx].val
	close := map[string]string{"(": ")", "[": "]", "{": "}"}[open]
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].kind != "op" {
			continue
		}
		if toks[i].val == open {
			depth++
		} else if toks[i].val == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return openIdx
}
