package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// simulateExec крайне грубо имитирует PHP-интерпретатор для тестового
// сервера: вытаскивает строку из echo "..."; остальное (в т.ч. сырые теги
// <?php) просто отдаёт как есть, как обычный статический файл.
func simulateExec(content string) string {
	start := strings.Index(content, `echo "`)
	if start < 0 {
		return content
	}
	start += len(`echo "`)
	end := strings.Index(content[start:], `"`)
	if end < 0 {
		return content
	}
	return content[start : start+end]
}

// newUploadTestServer эмулирует бэкенд, который блэклистит точное
// расширение ".php" на загрузке, хранит остальное в /uploads/<name> и
// "исполняет" (через simulateExec) только расширения из execExt.
func newUploadTestServer(t *testing.T, execExt map[string]bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	stored := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/upload.php" && r.Method == http.MethodPost:
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(400)
				return
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer file.Close()
			name := header.Filename
			if strings.HasSuffix(name, ".php") {
				w.WriteHeader(400)
				w.Write([]byte("rejected: расширение не разрешено"))
				return
			}
			data, _ := io.ReadAll(file)
			mu.Lock()
			stored[name] = string(data)
			mu.Unlock()
			w.Write([]byte("Загружено: uploads/" + name))
		case strings.HasPrefix(r.URL.Path, "/uploads/"):
			name := strings.TrimPrefix(r.URL.Path, "/uploads/")
			mu.Lock()
			content, ok := stored[name]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			ext := ""
			if i := strings.LastIndex(name, "."); i >= 0 {
				ext = name[i:]
			}
			if execExt[ext] {
				w.Write([]byte(simulateExec(content)))
			} else {
				w.Write([]byte(content))
			}
		default:
			w.Write([]byte(`<html><body><form action="/upload.php" method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="tok123"><input type="file" name="file"></form></body></html>`))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFileUploadConfirmedRCEViaAlternateExtension(t *testing.T) {
	server := newUploadTestServer(t, map[string]bool{".phtml": true, ".pht": true, ".php5": true})
	result, err := ScanFileUpload(context.Background(), FileUploadOptions{URL: server.URL + "/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Forms != 1 || result.Fields != 1 {
		t.Fatalf("%+v", result)
	}
	if len(result.Hits) != 1 {
		t.Fatalf("expected exactly 1 confirmed hit, got %+v", result.Hits)
	}
	h := result.Hits[0]
	if h.Filename != "wscan_shell.phtml" || !strings.Contains(h.ServedAt, "/uploads/wscan_shell.phtml") {
		t.Fatalf("unexpected hit: %+v", h)
	}
}

func TestFileUploadNoHitWhenNotExecutedOrRejected(t *testing.T) {
	// Ничего не исполняется (всё отдаётся как статика) — .php блэклистится на
	// загрузке, остальное хранится, но сервер не "запускает" PHP ни для
	// одного расширения, так что raw <?php всегда виден в ответе.
	server := newUploadTestServer(t, map[string]bool{})
	result, err := ScanFileUpload(context.Background(), FileUploadOptions{URL: server.URL + "/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hits) != 0 {
		t.Fatalf("expected no confirmed RCE on a server that never executes uploads, got %+v", result.Hits)
	}
}

func TestFileUploadNoFormOnPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>no forms here</body></html>"))
	}))
	defer server.Close()
	if _, err := ScanFileUpload(context.Background(), FileUploadOptions{URL: server.URL + "/"}, nil); err == nil {
		t.Fatal("expected error when page has no file-upload form")
	}
}

func TestFileUploadInputValidation(t *testing.T) {
	for _, o := range []FileUploadOptions{{URL: "file:///etc/passwd"}, {URL: "http://user:secret@example.org"}, {URL: "http://example.org", VirtualHost: "a b"}} {
		if _, err := ScanFileUpload(context.Background(), o, nil); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
