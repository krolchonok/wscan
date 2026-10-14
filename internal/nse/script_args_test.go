package nse

import (
	lua "github.com/yuin/gopher-lua"
	"testing"
)

func TestScriptArgsAliasesAndMultipleReturns(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	r := New("", Config{Args: map[string]string{"old.domain": "lab.local", "port": "53", "empty": ""}})
	L.SetGlobal("getargs", L.NewFunction(r.stdnseGetScriptArgs))
	if err := L.DoString(`
 local domain, missing, port, empty = getargs({'new.domain','old.domain'},'missing','port','empty')
 assert(domain=='lab.local' and missing==nil and port=='53' and empty=='')
 assert(select('#',getargs('missing','port'))==2)
 assert(select('#',getargs())==0)
 `); err != nil {
		t.Fatal(err)
	}
}
