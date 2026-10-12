// Package jsapi describes the JavaScript API our embedded engine implements.
package jsapi

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

var templateExpression = regexp.MustCompile(`\{\{[^}\n]+\}\}`)

// Modules returns only implemented modules, never placeholder APIs.
func Modules() []string {
	return []string{"nuclei/net", "nuclei/bytes", "nuclei/ssh", "nuclei/redis", "nuclei/mysql", "nuclei/postgres", "nuclei/smb", "nuclei/mssql", "nuclei/fs", "nuclei/vnc", "nuclei/rdp", "nuclei/ldap", "wscan/mailaudit"}
}

// ModuleError is shared by offline compatibility checks and runtime require().
func ModuleError(name string) error {
	name = strings.TrimPrefix(name, "./")
	for _, supported := range Modules() {
		if name == supported {
			return nil
		}
	}
	switch name {
	case "nuclei/oracle", "nuclei/rsync", "nuclei/smtp":
		return fmt.Errorf("JavaScript module %q is not implemented by the native engine", name)
	default:
		return fmt.Errorf("unknown JavaScript module %q", name)
	}
}

// CheckSource parses JavaScript without evaluating it or opening connections.
// Literal require() calls are checked against the same API as the runtime.
func CheckSource(source string) []string {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	// Expressions are rendered before execution. Validate their surrounding
	// JavaScript without pretending to evaluate the template variables here.
	source = templateExpression.ReplaceAllString(source, "wscan_template_value")
	program, err := parser.ParseFile(nil, "", source, 0)
	if err != nil {
		return []string{"JavaScript syntax: " + err.Error()}
	}
	reasons := map[string]bool{}
	walk(reflect.ValueOf(program), map[uintptr]bool{}, func(call *ast.CallExpression) {
		name, ok := call.Callee.(*ast.Identifier)
		if !ok || name.Name.String() != "require" {
			return
		}
		if len(call.ArgumentList) != 1 {
			reasons["JavaScript require() needs one literal module name"] = true
			return
		}
		literal, ok := call.ArgumentList[0].(*ast.StringLiteral)
		if !ok {
			reasons["dynamic JavaScript require() cannot be checked offline"] = true
			return
		}
		if err := ModuleError(literal.Value.String()); err != nil {
			reasons[err.Error()] = true
		}
	})
	var out []string
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

// goja has no public AST visitor. Traverse only AST structs, skipping file and
// source metadata; this also catches require() inside functions and branches.
func walk(v reflect.Value, seen map[uintptr]bool, visit func(*ast.CallExpression)) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return
		}
		if v.Kind() == reflect.Pointer {
			// Declaration lists can reference the same AST nodes as the body.
			// Visit each pointer once, keeping nested-function checks linear.
			pointer := v.Pointer()
			if seen[pointer] {
				return
			}
			seen[pointer] = true
		}
		if v.CanInterface() {
			if call, ok := v.Interface().(*ast.CallExpression); ok {
				visit(call)
			}
		}
		walk(v.Elem(), seen, visit)
	case reflect.Struct:
		if v.Type().PkgPath() != "github.com/dop251/goja/ast" {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			walk(v.Field(i), seen, visit)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i), seen, visit)
		}
	}
}
