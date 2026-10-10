package dsl

import (
	"net"
	"strings"
	"testing"
)

func TestEvalBool(t *testing.T) {
	env := map[string]any{
		"status_code":    float64(200),
		"content_length": float64(1024),
		"body":           "<html><title>Welcome Admin</title>Server: nginx/1.24.0</html>",
		"header":         "Server: nginx/1.24.0\nContent-Type: text/html",
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`status_code == 200`, true},
		{`status_code == 404`, false},
		{`status_code >= 200 && status_code < 300`, true},
		{`contains(body, "Welcome Admin")`, true},
		{`contains(body, "nope")`, false},
		{`contains_all(body, "Welcome", "Admin")`, true},
		{`contains_all(body, "Welcome", "Missing")`, false},
		{`contains_any(body, "Missing", "Admin")`, true},
		{`to_lower(body) == to_lower(body)`, true},
		{`icontains(body, "welcome admin")`, true},
		{`regex("nginx/[0-9.]+", body)`, true},
		{`regex("apache/[0-9.]+", body)`, false},
		{`len(body) > 10`, true},
		{`status_code == 200 && contains(header, "nginx")`, true},
		{`!(status_code == 404)`, true},
		{`starts_with(body, "<html>")`, true},
		{`compare_versions("1.24.0", ">1.0.0", "<2.0.0")`, true},
		{`compare_versions("2.4.7", ">2.5.0")`, false},
		{`status_code == 200 || status_code == 301`, true},
		{`missing_var == ""`, true},
	}
	for _, c := range cases {
		got, err := EvalBool(c.expr, env)
		if err != nil {
			t.Errorf("%s: error %v", c.expr, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.expr, got, c.want)
		}
	}
}

func TestEvalString(t *testing.T) {
	v, err := Eval(`concat("a", "b", "c")`, nil)
	if err != nil || v.(string) != "abc" {
		t.Fatalf("concat: %v %v", v, err)
	}
	v, err = Eval(`md5("")`, nil)
	if err != nil || v.(string) != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("md5: %v %v", v, err)
	}
}

func TestHMAC(t *testing.T) {
	v, err := Eval(`hmac("sha256", "data", "key")`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// echo -n data | openssl dgst -sha256 -hmac key
	want := "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"
	if v.(string) != want {
		t.Fatalf("hmac: got %v want %s", v, want)
	}
}

func TestRandIP(t *testing.T) {
	v, err := Eval(`rand_ip()`, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := v.(string)
	if net.ParseIP(s) == nil {
		t.Fatalf("rand_ip: not an IP: %q", s)
	}
}

func TestJavaGadgetURLDNS(t *testing.T) {
	v, err := Eval(`generate_java_gadget("dns", "oast.example", "hex")`, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := v.(string)
	if len(s) < 20 {
		t.Fatalf("gadget too short: %q", s)
	}
	// Must start with Java serialization magic aced0005
	if !strings.HasPrefix(s, "aced0005") {
		t.Fatalf("expected java stream magic, got %q", s[:min(16, len(s))])
	}
}

func TestAESCBC(t *testing.T) {
	// Encrypt then ensure non-empty binary output.
	v, err := Eval(`aes_cbc("hello-world!!!!!", "0123456789abcdef", "0123456789abcdef")`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.(string)) == 0 {
		t.Fatal("aes_cbc returned empty")
	}
}

func TestEvalErrors(t *testing.T) {
	if _, err := Eval(`unknown_fn(1)`, nil); err == nil {
		t.Error("expected error for unknown function")
	}
	if _, err := Eval(`status_code ==`, nil); err == nil {
		t.Error("expected parse error")
	}
}
