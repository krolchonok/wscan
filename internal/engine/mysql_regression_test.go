package engine

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"wscan/internal/domain"
)

func TestCVE20122122NetworkFailureDoesNotLoopUntilJSTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var count atomic.Int32
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			c.Close()
		}
	}()
	tvars := map[string]string{"Host": "127.0.0.1", "Port": strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}
	tmpl := domain.Template{ID: "CVE-2012-2122"}
	req := domain.JavaScriptRequest{Code: `while(true){try{throw "bad";}catch{}}`, Args: map[string]any{"User": "root", "Pass": "wrong", "Query": "SHOW DATABASES"}, Matchers: []domain.Matcher{{Type: "dsl", DSL: []string{"success == true"}}}}
	started := time.Now()
	findings, errs, _ := execJavaScript(context.Background(), tmpl, req, "127.0.0.1", nil, tvars, "", time.Second)
	if len(findings) != 0 || len(errs) != 1 || strings.Contains(errs[0].Error(), "javascript timeout") || count.Load() != 1 || time.Since(started) > time.Second {
		t.Fatalf("findings=%v errors=%v attempts=%d", findings, errs, count.Load())
	}
}
