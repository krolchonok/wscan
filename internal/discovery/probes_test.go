package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
)

func TestAllLibraryServiceSignaturesLoad(t *testing.T) {
	root := filepath.Join("..", "..", "library")
	if _, err := os.Stat(filepath.Join(root, "nmap", "nmap-service-probes")); os.IsNotExist(err) {
		t.Skip("full check library not installed")
	}
	db := loadProbes(root)
	if db.report.Signatures < 12000 || db.report.Loaded != db.report.Signatures || len(db.report.Errors) > 0 {
		t.Fatalf("incomplete signature database: %+v", db.report)
	}
	t.Logf("%d probes, %d signatures", db.report.Probes, db.report.Loaded)
}

func TestProbeBinaryCapturesFallbackAndSoftMatch(t *testing.T) {
	db := parseProbes(strings.NewReader(`Exclude T:9100-9107,U:123
Probe TCP NULL q||
match example m|^\xff(\x01\x02)(A_B)(W\0R\0T\0)$| p/$P(3)/ v/$I(1,">").$SUBST(2,"_",".")/ i/banner/ h/host/ o/Linux/ d/router/ cpe:/a:example:$2/
Probe TCP Query q|\x00\r\n|
fallback NULL
softmatch other m|^\xff|
`))
	if len(db.report.Errors) > 0 {
		t.Fatal(db.report.Errors)
	}
	p := db.byName["tcp:Query"]
	if string(p.payload) != "\x00\r\n" || !db.excluded["tcp"][9107] || !db.excluded["udp"][123] || db.excluded["tcp"][123] {
		t.Fatal("payload or exclusions")
	}
	got, hard := db.match(context.Background(), p, []byte("\xff\x01\x02A_BW\x00R\x00T\x00"), domain.Service{})
	if !hard || got.Name != "example" || got.Product != "WRT" || got.Version != "258.A.B" {
		t.Fatalf("got %+v, hard %v", got, hard)
	}
	if got.Info != "banner" || got.DetectedHostname != "host" || got.OS != "Linux" || got.DeviceType != "router" || len(got.CPE) != 1 || got.CPE[0] != "cpe:/a:example:a_b" {
		t.Fatal(got)
	}
}

func TestProbeOctalASCIIAndLiteralBackslash(t *testing.T) {
	db := parseProbes(strings.NewReader("Probe TCP NULL q||\nmatch example m|^\\040\\w\\\\0$| p/Example/\n"))
	if len(db.report.Errors) > 0 {
		t.Fatal(db.report.Errors)
	}
	p := db.byName["tcp:NULL"]
	if _, hard := db.match(context.Background(), p, []byte(" A\\0"), domain.Service{}); !hard {
		t.Fatal("octal or literal backslash did not match")
	}
	if _, hard := db.match(context.Background(), p, []byte(" \xff\\0"), domain.Service{}); hard {
		t.Fatal("PCRE byte word class matched a non-ASCII byte")
	}
}

func TestGenericSignaturePreservesOnlySameProtocolProduct(t *testing.T) {
	db := parseProbes(strings.NewReader("Probe TCP NULL q||\nmatch http m|^HTTP/|\n"))
	p := db.byName["tcp:NULL"]
	for _, previous := range []string{"http", "ftp"} {
		got, hard := db.match(context.Background(), p, []byte("HTTP/1.0 200 OK\r\n"), domain.Service{Name: previous, Product: "Existing", Version: "1.2"})
		if !hard {
			t.Fatal("expected protocol match")
		}
		if previous == "http" && (got.Product != "Existing" || got.Version != "1.2") {
			t.Fatal(got)
		}
		if previous == "ftp" && (got.Product != "" || got.Version != "") {
			t.Fatal("stale product from another protocol", got)
		}
	}
}

func TestNoVersionDoesNotSendServiceProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	read := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		read <- n
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	scanner := Scanner{Config: Config{NoVersion: true, Ports: []int{port}, LibraryDir: filepath.Join("..", "..", "library")}}
	services, err := scanner.Scan(context.Background(), "127.0.0.1")
	if err != nil || len(services) != 1 {
		t.Fatalf("%+v %v", services, err)
	}
	select {
	case n := <-read:
		if n != 0 {
			t.Fatal("service probe sent with NoVersion")
		}
	case <-time.After(time.Second):
		t.Fatal("scanner did not close connection")
	}
}

func TestProbeOpenWrtWithoutServerHeader(t *testing.T) {
	root := filepath.Join("..", "..", "library")
	if _, err := os.Stat(filepath.Join(root, "nmap", "nmap-service-probes")); os.IsNotExist(err) {
		t.Skip("full library not installed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan string, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				line, _ := bufio.NewReader(conn).ReadString('\n')
				requests <- line
				if strings.HasPrefix(line, "GET / HTTP/1.0") {
					fmt.Fprint(conn, "HTTP/1.0 200 OK\r\nConnection: close\r\nETag: \"abc-def-123\"\r\nLast-Modified: Tue, 01 Oct 2024 12:00:00 GMT\r\nDate: Tue, 01 Oct 2024 12:00:00 GMT\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok")
				}
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	service := domain.Service{Host: "127.0.0.1", Port: port, Protocol: "tcp", Name: "http"}
	got := identifyProbeService(context.Background(), service, root, time.Second, nil)
	if got.Name != "http" || got.Product != "OpenWrt uHTTPd" || got.Version != "" {
		t.Fatalf("unexpected fingerprint: %+v", got)
	}
	select {
	case line := <-requests:
		if line != "GET / HTTP/1.0\r\n" {
			t.Fatal(line)
		}
	case <-time.After(time.Second):
		t.Fatal("no GET probe")
	}
}

func TestProbeExclusionAndCancelledContextDoNotConnect(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nmap"), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	data := fmt.Sprintf("Exclude T:%d\nProbe TCP Query q|GET / HTTP/1.0\\r\\n\\r\\n|\nmatch http m|^HTTP/| p/Example/\n", port)
	if err := os.WriteFile(filepath.Join(root, "nmap", "nmap-service-probes"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	service := domain.Service{Host: "127.0.0.1", Port: port, Protocol: "tcp"}
	got := identifyProbeService(context.Background(), service, root, time.Second, nil)
	if got.Product != "" {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service.Port++
	_ = identifyProbeService(ctx, service, root, time.Second, nil)
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("excluded endpoint contacted")
	}
}
