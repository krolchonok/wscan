// Package dsl implements a self-contained evaluator for the expression
// language used in Nuclei "dsl" matchers and extractors. It is intentionally
// our own small engine (no third-party expression library and no external
// nuclei binary): it reads the expression a template already ships and decides
// what it means. Coverage is a practical subset of Nuclei's helper functions —
// the string/comparison/encoding helpers that matchers actually use — not the
// request-construction helpers (rand_*, payloads, interactsh), which belong to
// features this engine does not execute.
package dsl

import (
	"fmt"
	"strconv"
	"strings"
)

// Eval parses and evaluates expr against env (variable name → value). Values
// are string, float64 or bool. Missing variables evaluate to an empty string,
// matching Nuclei's lenient behavior for absent response fields.
func Eval(expr string, env map[string]any) (any, error) {
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: toks}
	node, err := p.parseExpression(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("unexpected trailing token %q", p.tokens[p.pos].val)
	}
	return node.eval(env)
}

// EvalBool evaluates expr and coerces the result to a boolean the way a matcher
// condition does.
func EvalBool(expr string, env map[string]any) (bool, error) {
	v, err := Eval(expr, env)
	if err != nil {
		return false, err
	}
	return truthy(v), nil
}

// --- lexer ---------------------------------------------------------------

type tokenKind int

const (
	tNumber tokenKind = iota
	tString
	tIdent
	tOp
	tLParen
	tRParen
	tComma
)

type token struct {
	kind tokenKind
	val  string
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")"})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ","})
			i++
		case c == '"' || c == '\'':
			str, n, err := lexString(s[i:], c)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tString, str})
			i += n
		case c >= '0' && c <= '9' || (c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			toks = append(toks, token{tNumber, s[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			word := s[i:j]
			switch word {
			case "true", "false":
				toks = append(toks, token{tIdent, word})
			default:
				toks = append(toks, token{tIdent, word})
			}
			i = j
		default:
			op, n := lexOperator(s[i:])
			if n == 0 {
				return nil, fmt.Errorf("unexpected character %q", string(c))
			}
			toks = append(toks, token{tOp, op})
			i += n
		}
	}
	return toks, nil
}

func lexString(s string, quote byte) (string, int, error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '"', '\'':
				b.WriteByte(next)
			default:
				b.WriteByte('\\')
				b.WriteByte(next)
			}
			i += 2
			continue
		}
		if c == quote {
			return b.String(), i + 1, nil
		}
		b.WriteByte(c)
		i++
	}
	return "", 0, fmt.Errorf("unterminated string literal")
}

func lexOperator(s string) (string, int) {
	two := ""
	if len(s) >= 2 {
		two = s[:2]
	}
	switch two {
	case "==", "!=", "<=", ">=", "&&", "||":
		return two, 2
	}
	switch s[0] {
	case '<', '>', '!', '+', '-', '*', '/', '%':
		return string(s[0]), 1
	}
	return "", 0
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

// --- parser (Pratt) ------------------------------------------------------

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos], true
	}
	return token{}, false
}

var binPrec = map[string]int{
	"||": 1, "&&": 2,
	"==": 3, "!=": 3,
	"<": 4, ">": 4, "<=": 4, ">=": 4,
	"+": 5, "-": 5,
	"*": 6, "/": 6, "%": 6,
}

func (p *parser) parseExpression(minPrec int) (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tOp {
			break
		}
		prec, isBin := binPrec[t.val]
		if !isBin || prec < minPrec {
			break
		}
		p.pos++
		right, err := p.parseExpression(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op: t.val, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	t, ok := p.peek()
	if ok && t.kind == tOp && (t.val == "!" || t.val == "-") {
		p.pos++
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryNode{op: t.val, operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	switch t.kind {
	case tNumber:
		p.pos++
		f, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, err
		}
		return &literalNode{value: f}, nil
	case tString:
		p.pos++
		return &literalNode{value: t.val}, nil
	case tIdent:
		p.pos++
		if t.val == "true" {
			return &literalNode{value: true}, nil
		}
		if t.val == "false" {
			return &literalNode{value: false}, nil
		}
		// function call?
		if next, ok := p.peek(); ok && next.kind == tLParen {
			p.pos++
			args, err := p.parseArgs()
			if err != nil {
				return nil, err
			}
			return &callNode{name: t.val, args: args}, nil
		}
		return &varNode{name: t.val}, nil
	case tLParen:
		p.pos++
		inner, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		if next, ok := p.peek(); !ok || next.kind != tRParen {
			return nil, fmt.Errorf("expected )")
		}
		p.pos++
		return inner, nil
	}
	return nil, fmt.Errorf("unexpected token %q", t.val)
}

func (p *parser) parseArgs() ([]node, error) {
	var args []node
	if next, ok := p.peek(); ok && next.kind == tRParen {
		p.pos++
		return args, nil
	}
	for {
		arg, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		next, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("expected , or ) in argument list")
		}
		if next.kind == tComma {
			p.pos++
			continue
		}
		if next.kind == tRParen {
			p.pos++
			return args, nil
		}
		return nil, fmt.Errorf("expected , or ) in argument list, got %q", next.val)
	}
}

// --- AST -----------------------------------------------------------------

type node interface {
	eval(env map[string]any) (any, error)
}

type literalNode struct{ value any }

func (n *literalNode) eval(map[string]any) (any, error) { return n.value, nil }

type varNode struct{ name string }

func (n *varNode) eval(env map[string]any) (any, error) {
	if v, ok := env[n.name]; ok {
		return v, nil
	}
	return "", nil
}

type unaryNode struct {
	op      string
	operand node
}

func (n *unaryNode) eval(env map[string]any) (any, error) {
	v, err := n.operand.eval(env)
	if err != nil {
		return nil, err
	}
	switch n.op {
	case "!":
		return !truthy(v), nil
	case "-":
		return -toNumber(v), nil
	}
	return nil, fmt.Errorf("unknown unary operator %q", n.op)
}

type binaryNode struct {
	op          string
	left, right node
}

func (n *binaryNode) eval(env map[string]any) (any, error) {
	// Short-circuit boolean operators.
	if n.op == "&&" || n.op == "||" {
		l, err := n.left.eval(env)
		if err != nil {
			return nil, err
		}
		if n.op == "&&" && !truthy(l) {
			return false, nil
		}
		if n.op == "||" && truthy(l) {
			return true, nil
		}
		r, err := n.right.eval(env)
		if err != nil {
			return nil, err
		}
		return truthy(r), nil
	}
	l, err := n.left.eval(env)
	if err != nil {
		return nil, err
	}
	r, err := n.right.eval(env)
	if err != nil {
		return nil, err
	}
	switch n.op {
	case "==":
		return looseEqual(l, r), nil
	case "!=":
		return !looseEqual(l, r), nil
	case "<":
		return toNumber(l) < toNumber(r), nil
	case ">":
		return toNumber(l) > toNumber(r), nil
	case "<=":
		return toNumber(l) <= toNumber(r), nil
	case ">=":
		return toNumber(l) >= toNumber(r), nil
	case "+":
		// Numeric when both look numeric, otherwise string concatenation.
		if isNumeric(l) && isNumeric(r) {
			return toNumber(l) + toNumber(r), nil
		}
		return toString(l) + toString(r), nil
	case "-":
		return toNumber(l) - toNumber(r), nil
	case "*":
		return toNumber(l) * toNumber(r), nil
	case "/":
		d := toNumber(r)
		if d == 0 {
			return float64(0), nil
		}
		return toNumber(l) / d, nil
	case "%":
		d := int64(toNumber(r))
		if d == 0 {
			return float64(0), nil
		}
		return float64(int64(toNumber(l)) % d), nil
	}
	return nil, fmt.Errorf("unknown operator %q", n.op)
}

type callNode struct {
	name string
	args []node
}

func (n *callNode) eval(env map[string]any) (any, error) {
	fn, ok := functions[n.name]
	if !ok {
		return nil, fmt.Errorf("unsupported dsl function %q", n.name)
	}
	vals := make([]any, len(n.args))
	for i, a := range n.args {
		v, err := a.eval(env)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return fn(vals)
}
