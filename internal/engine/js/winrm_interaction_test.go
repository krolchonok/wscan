package js

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/masterzen/winrm"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"wscan/internal/domain"
)

func soapWinRM(action, body string) string {
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>` + action + `</a:Action></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}

// A local WS-Man/WinRS server exercises the real HTTP, SOAP and base64 paths.
// It models command results; it does not execute PowerShell or emulate Windows.
func winRMFixture(t *testing.T, run func(string) (string, string, int)) (WinRMOptions, func()) {
	t.Helper()
	var mu sync.Mutex
	outputs := map[string]string{}
	errors := map[string]string{}
	codes := map[string]int{}
	next := 0
	type sessionFixture struct {
		marker string
		output chan string
		closed chan struct{}
		once   sync.Once
	}
	sessions := map[string]*sessionFixture{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var request struct {
			Header struct {
				Action      string `xml:"Action"`
				SelectorSet struct {
					Selectors []struct {
						Name  string `xml:"Name,attr"`
						Value string `xml:",chardata"`
					} `xml:"Selector"`
				} `xml:"SelectorSet"`
			} `xml:"Header"`
			Body struct {
				Send struct {
					Stream struct {
						Value     string `xml:",chardata"`
						CommandID string `xml:"CommandId,attr"`
					} `xml:"Stream"`
				} `xml:"Send"`
				Signal struct {
					CommandID string `xml:"CommandId,attr"`
				} `xml:"Signal"`
				CommandLine struct {
					Command string `xml:"Command"`
				} `xml:"CommandLine"`
				Receive struct {
					DesiredStream struct {
						CommandID string `xml:"CommandId,attr"`
					} `xml:"DesiredStream"`
				} `xml:"Receive"`
			} `xml:"Body"`
		}
		if err := xml.Unmarshal(raw, &request); err != nil {
			t.Errorf("invalid SOAP: %v", err)
			http.Error(w, "bad SOAP", 400)
			return
		}
		action := request.Header.Action
		w.Header().Set("Content-Type", "application/soap+xml")
		switch {
		case strings.HasSuffix(action, "/Create"):
			fmt.Fprint(w, soapWinRM(action+"Response", `<rsp:Shell><rsp:ShellId>fixture</rsp:ShellId></rsp:Shell>`))
		case strings.HasSuffix(action, "/Command"):
			command := request.Body.CommandLine.Command
			encoded := strings.TrimPrefix(command, "powershell.exe -EncodedCommand ")
			b, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Error(err)
			}
			units := make([]uint16, len(b)/2)
			for i := range units {
				units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
			}
			script := string(utf16.Decode(units))
			out, stderr, code := run(script)
			mu.Lock()
			next++
			id := strconv.Itoa(next)
			outputs[id] = out
			if strings.Contains(script, "while(($__wscan_line") {
				marker := regexp.MustCompile(`WSCAN:[a-f0-9]+:`).FindString(script)
				sessions[id] = &sessionFixture{marker: marker, output: make(chan string, 1), closed: make(chan struct{})}
			}
			errors[id] = stderr
			codes[id] = code
			mu.Unlock()
			fmt.Fprint(w, soapWinRM(action+"Response", "<rsp:CommandId>"+id+"</rsp:CommandId>"))
		case strings.HasSuffix(action, "/Send"):
			id := request.Body.Send.Stream.CommandID
			encoded, _ := base64.StdEncoding.DecodeString(request.Body.Send.Stream.Value)
			scriptBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil {
				t.Error(err)
			}
			out, _, code := run(string(scriptBytes))
			mu.Lock()
			session := sessions[id]
			mu.Unlock()
			if session == nil {
				t.Errorf("stdin sent to unknown process %s", id)
				break
			}
			reply, _ := json.Marshal(WinRMShellOutput{Output: out, Directory: `C:\Users`, ExitCode: code})
			session.output <- session.marker + string(reply) + "\n"
			fmt.Fprint(w, soapWinRM(action+"Response", ""))
		case strings.HasSuffix(action, "/Signal"):
			mu.Lock()
			session := sessions[request.Body.Signal.CommandID]
			mu.Unlock()
			if session != nil {
				session.once.Do(func() { close(session.closed) })
			}
			fmt.Fprint(w, soapWinRM(action+"Response", ""))
		case strings.HasSuffix(action, "/Receive"):
			id := request.Body.Receive.DesiredStream.CommandID
			mu.Lock()
			out, stderr, code, session := outputs[id], errors[id], codes[id], sessions[id]
			mu.Unlock()
			state := "Done"
			if session != nil {
				state = "Running"
				out = ""
				stderr = ""
				select {
				case out = <-session.output:
				case <-session.closed:
					state = "Done"
				case <-time.After(100 * time.Millisecond):
				}
			}
			body := fmt.Sprintf(`<rsp:ReceiveResponse><rsp:Stream Name="stdout">%s</rsp:Stream><rsp:Stream Name="stderr">%s</rsp:Stream><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/%s"><rsp:ExitCode>%d</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, base64.StdEncoding.EncodeToString([]byte(out)), base64.StdEncoding.EncodeToString([]byte(stderr)), state, code)
			fmt.Fprint(w, soapWinRM(action+"Response", body))
		default:
			fmt.Fprint(w, soapWinRM(action+"Response", ""))
		}
	}))
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	return WinRMOptions{Host: u.Hostname(), Port: port, HTTPS: true, Insecure: true, Timeout: time.Second, Credential: domain.Credential{Type: "password", Username: "fixture", Secret: "fixture-password"}, transportFactory: func(dial func(string, string) (net.Conn, error)) winrm.Transporter {
		return winrm.NewClientWithDial(dial)
	}}, server.Close
}

func TestWinRMDirectoryJSONAndLiteralPaths(t *testing.T) {
	const remote = `C:\Users\O'Brien`
	opts, close := winRMFixture(t, func(script string) (string, string, int) {
		if !strings.Contains(script, `$p='C:\Users\O''Brien'`) || !strings.Contains(script, "Get-Acl -LiteralPath $item.FullName") {
			t.Errorf("unsafe or missing literal path: %s", script)
		}
		return `{"path":"C:\\Users\\O'Brien","parent":"C:\\Users","entries":[{"name":"notes.txt","path":"C:\\Users\\O'Brien\\notes.txt","directory":false,"size":12,"owner":"CORP\\alice","rights":"CORP\\alice: Read [Allow]"}]}`, "", 0
	})
	defer close()
	directory, err := BrowseWinRM(context.Background(), opts, remote)
	if err != nil || directory.Path != remote || len(directory.Entries) != 1 || directory.Entries[0].Owner != `CORP\alice` {
		t.Fatalf("directory=%+v err=%v", directory, err)
	}
}

func TestWinRMPreviewAndDownload(t *testing.T) {
	content := bytes.Repeat([]byte("hello\x00"), 10000)
	opts, close := winRMFixture(t, func(script string) (string, string, int) {
		var offset, count int
		seek := strings.Split(script, "$null=$f.Seek(")
		if len(seek) != 2 {
			t.Errorf("missing seek")
			return "", "invalid", 1
		}
		_, _ = fmt.Sscanf(seek[1], "%d,", &offset)
		alloc := strings.Split(script, "$b=New-Object byte[] ")
		_, _ = fmt.Sscanf(alloc[1], "%d;", &count)
		hi := offset + count
		if hi > len(content) {
			hi = len(content)
		}
		return base64.StdEncoding.EncodeToString(content[offset:hi]) + "\r\n", "", 0
	})
	defer close()
	var preview bytes.Buffer
	n, err := ReadWinRMFile(context.Background(), opts, `C:\test.bin`, &preview, 9)
	if err != nil || n != 9 || !bytes.Equal(preview.Bytes(), content[:9]) {
		t.Fatalf("preview=%v n=%d err=%v", preview.Bytes(), n, err)
	}
	path, err := DownloadWinRM(context.Background(), opts, `C:\test.bin`, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, content) {
		t.Fatal("download corrupted")
	}
}

func TestWinRMDownloadFailureRemovesPartialFile(t *testing.T) {
	opts, close := winRMFixture(t, func(string) (string, string, int) { return "", "Access denied", 1 })
	defer close()
	directory := t.TempDir()
	_, err := DownloadWinRM(context.Background(), opts, `C:\denied.txt`, directory)
	files, _ := os.ReadDir(directory)
	if err == nil || len(files) != 0 {
		t.Fatalf("err=%v files=%v", err, files)
	}
}

func TestWinRMTLSVerificationAndBoundedOutput(t *testing.T) {
	opts, close := winRMFixture(t, func(string) (string, string, int) { return strings.Repeat("x", 100), "stderr", 7 })
	defer close()
	opts.Insecure = false
	if _, _, _, err := RunWinRMPowerShell(context.Background(), opts, "whoami", 8); err == nil {
		t.Fatal("untrusted certificate was accepted")
	}
	opts.Insecure = true
	out, stderr, code, err := RunWinRMPowerShell(context.Background(), opts, "whoami", 8)
	if err != nil || !strings.HasPrefix(out, "xxxxxxxx\n") || !strings.Contains(out, "обрезан") || stderr != "stderr" || code != 7 {
		t.Fatalf("out=%q stderr=%q code=%d err=%v", out, stderr, code, err)
	}
}

func TestWinRMCanceledConnection(t *testing.T) {
	opts := WinRMOptions{Host: "127.0.0.1", Port: 1, Credential: domain.Credential{Type: "password", Username: "user"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := RunWinRMPowerShell(ctx, opts, "whoami", 10); err == nil {
		t.Fatal("canceled command succeeded")
	}
	opts.Credential.Type = "ntlm-hash"
	if _, err := newInteractionWinRM(context.Background(), opts); err == nil {
		t.Fatal("hash was used as a password")
	}
}

func TestWinRMShellReusesProcessAndCloses(t *testing.T) {
	counter, processes := 0, 0
	opts, closeServer := winRMFixture(t, func(script string) (string, string, int) {
		if strings.Contains(script, "while(($__wscan_line") {
			processes++
			return "", "", 0
		}
		switch script {
		case "$counter=42":
			counter = 42
			return "", "", 0
		case "$counter":
			return strconv.Itoa(counter), "", 0
		default:
			t.Errorf("unexpected shell command %q", script)
			return "", "", 1
		}
	})
	defer closeServer()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shell, err := OpenWinRMShell(ctx, opts, `C:\Users`)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	if _, err = shell.Run(ctx, "$counter=42"); err != nil {
		t.Fatal(err)
	}
	reply, err := shell.Run(ctx, "$counter")
	if err != nil || reply.Output != "42" || processes != 1 {
		t.Fatalf("reply=%+v processes=%d err=%v", reply, processes, err)
	}
	shell.Close()
	select {
	case <-shell.replies:
	case <-time.After(time.Second):
		t.Fatal("session did not close")
	}
}

// Optional end-to-end verification on an explicitly configured Windows host.
func TestWinRMWindowsIntegration(t *testing.T) {
	host := os.Getenv("WSCAN_TEST_WINRM_HOST")
	if host == "" {
		t.Skip("set WSCAN_TEST_WINRM_HOST and credentials for Windows integration")
	}
	port := 5985
	if value := os.Getenv("WSCAN_TEST_WINRM_PORT"); value != "" {
		var err error
		port, err = strconv.Atoi(value)
		if err != nil {
			t.Fatal("invalid WinRM test port")
		}
	}
	opts := WinRMOptions{Host: host, Port: port, HTTPS: port == 5986, Insecure: os.Getenv("WSCAN_TEST_WINRM_INSECURE") == "1", Timeout: 10 * time.Second, Credential: domain.Credential{Type: "password", Domain: os.Getenv("WSCAN_TEST_WINRM_DOMAIN"), Username: os.Getenv("WSCAN_TEST_WINRM_USER"), Secret: os.Getenv("WSCAN_TEST_WINRM_PASSWORD")}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := WinRMIdentity(ctx, opts); err != nil {
		t.Fatalf("WinRM login failed: %v", err)
	}
	directory, err := BrowseWinRM(ctx, opts, "")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := OpenWinRMShell(ctx, opts, directory.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.CloseAndWait(context.Background())
	if _, err = shell.Run(ctx, "$wscanTestCounter=42"); err != nil {
		t.Fatal(err)
	}
	result, err := shell.Run(ctx, "$wscanTestCounter")
	if err != nil || strings.TrimSpace(result.Output) != "42" {
		t.Fatalf("PowerShell variables did not persist: %v", err)
	}
}
