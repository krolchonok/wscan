package nse

import (
	"context"
	"fmt"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/ast"
	"github.com/yuin/gopher-lua/parse"
)

// Parse declarations without evaluating Lua, including InitScript's multiple
// assignment. Strings/comments and local variables must not look like rules.
func declaredRules(source []byte) (map[string]bool, error) {
	chunk, err := parse.Parse(strings.NewReader(transformLua53(string(source))), "catalogue")
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	var walk func([]ast.Stmt, map[string]bool)
	walk = func(stmts []ast.Stmt, parent map[string]bool) {
		locals := map[string]bool{}
		for name, value := range parent {
			locals[name] = value
		}
		for _, stmt := range stmts {
			switch s := stmt.(type) {
			case *ast.LocalAssignStmt:
				for _, name := range s.Names {
					locals[name] = true
				}
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if name, ok := lhs.(*ast.IdentExpr); ok && !locals[name.Value] {
						found[name.Value] = true
					}
				}
			case *ast.FuncDefStmt:
				if name, ok := s.Name.Func.(*ast.IdentExpr); ok && !locals[name.Value] {
					found[name.Value] = true
				}
			case *ast.DoBlockStmt:
				walk(s.Stmts, locals)
			case *ast.IfStmt:
				walk(s.Then, locals)
				walk(s.Else, locals)
			}
		}
	}
	walk(chunk, nil)
	return found, nil
}
func declaresRule(source []byte, name string) bool {
	rules, err := declaredRules(source)
	return err == nil && rules[name]
}

// CheckSource checks that an NSE script's requires resolve against nselib and
// that it declares action + portrule/hostrule. Full Lua execution of heavy
// libraries is skipped here so catalog sync stays fast; Run() loads for real.
func CheckSource(source []byte, libraryDir string) error {
	r := New(libraryDir, Config{})
	if err := r.checkRequiresAvailable(source); err != nil {
		return err
	}
	rules, err := declaredRules(source)
	if err != nil {
		return fmt.Errorf("NSE: ошибка разбора Lua: %w", err)
	}
	if !rules["action"] {
		return fmt.Errorf("нет функции action")
	}
	if !rules["portrule"] && !rules["hostrule"] && !rules["prerule"] {
		return fmt.Errorf("нет portrule/hostrule/prerule")
	}

	return nil
}

// CheckSourceExec fully loads the script in a sandboxed Lua state (used by tests).
func CheckSourceExec(source []byte, libraryDir string) error {
	networkCtx, stopNetwork := context.WithCancel(context.Background())
	stopNetwork()
	ctrl := newControl(networkCtx, Config{})
	defer ctrl.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	L := lua.NewState()
	defer L.Close()
	L.SetContext(ctx)
	sandbox(L)
	for _, name := range []string{"io", "os", "debug", "print"} {
		L.SetGlobal(name, lua.LNil)
	}
	pkg := L.GetGlobal("package")
	loaded := L.GetField(pkg, "loaded")
	for _, name := range []string{"io", "os", "debug"} {
		L.SetField(loaded, name, lua.LNil)
	}
	L.SetField(pkg, "cpath", lua.LString(""))
	registerSocketType(L)
	r := New(libraryDir, Config{})
	r.registerModules(L, ctrl, "library-check")
	L.SetGlobal("SCRIPT_NAME", lua.LString("library-check"))
	L.SetGlobal("SCRIPT_TYPE", lua.LString("portrule"))
	if err := L.DoString(transformLua53(string(source))); err != nil {
		return err
	}
	if _, ok := L.GetGlobal("action").(*lua.LFunction); !ok {
		return fmt.Errorf("нет функции action")
	}
	_, port := L.GetGlobal("portrule").(*lua.LFunction)
	_, host := L.GetGlobal("hostrule").(*lua.LFunction)
	if !port && !host {
		return fmt.Errorf("нет portrule/hostrule")
	}
	return nil
}
