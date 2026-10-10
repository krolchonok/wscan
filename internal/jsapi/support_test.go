package jsapi

import (
	"strings"
	"testing"
)

func TestCheckSourceModuleImports(t *testing.T) {
	for _, tc := range []struct{ name, source, reason string }{
		{"implemented", `const c = require("nuclei/ssh"); c;`, ""},
		{"template-expression", `var port = {{Port}}; require("nuclei/ssh");`, ""},
		{"prefix", `require('./nuclei/net');`, ""},
		{"oracle", `require("nuclei/oracle");`, "not implemented"},
		{"nested", `function check(){ return require("nuclei/rsync"); }`, "not implemented"},
		{"unknown", `require("nuclei/no-such-module");`, "unknown"},
		{"dynamic", `require(moduleName);`, "dynamic"},
		{"comment", `// require("nuclei/oracle")
true;`, ""},
		{"string", `var text = 'require("nuclei/oracle")';`, ""},
		{"escaped", `require("nuclei/\x73mtp");`, "not implemented"},
		{"syntax", `const = ;`, "syntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reasons := CheckSource(tc.source)
			if tc.reason == "" && len(reasons) != 0 {
				t.Fatalf("unexpected: %v", reasons)
			}
			if tc.reason != "" && !strings.Contains(strings.Join(reasons, "; "), tc.reason) {
				t.Fatalf("expected %q, got %v", tc.reason, reasons)
			}
		})
	}
}

func TestCheckSourceNestedDeclarations(t *testing.T) {
	source := `require("nuclei/oracle");`
	for i := 0; i < 24; i++ {
		source = "var nested = function(){" + source + "};"
	}
	reasons := CheckSource(source)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "not implemented") {
		t.Fatalf("nested import was missed: %v", reasons)
	}
}
