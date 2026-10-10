package js

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func TestSMBDownloadRemovesFailedPartialFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	if _, err := DownloadSMB(ctx, "127.0.0.1", 445, "Public", "file.txt", dir); err == nil {
		t.Fatal("canceled download succeeded")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatal("failed download left a partial local file")
	}
}

// Opt-in integration test against a local anonymous SMB2 test share.
func TestSMBBrowserIntegration(t *testing.T) {
	address := os.Getenv("WSCAN_TEST_SMB_ADDRESS")
	if address == "" {
		t.Skip("set WSCAN_TEST_SMB_ADDRESS for local SMB integration")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	shares, err := BrowseSMB(ctx, host, port, "", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, share := range shares {
		if share.Name == "Public" {
			found = true
			expectedWrite := os.Getenv("WSCAN_TEST_SMB_WRITE") == "1"
			if share.Read == nil || !*share.Read || share.Write == nil || *share.Write != expectedWrite || share.AccessError != "" {
				t.Fatalf("unexpected share permissions: %+v", share)
			}
		}
	}
	if !found {
		t.Fatal("Public share was not enumerated")
	}
	entries, err := BrowseSMB(ctx, host, port, "Public", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 || !entries[0].Directory {
		t.Fatalf("directory listing: %v", entries)
	}
	var data bytes.Buffer
	if _, err := ReadSMBFile(ctx, host, port, "Public", "hello.txt", &data, 5); err != nil {
		t.Fatal(err)
	}
	if data.String() != "hello" {
		t.Fatalf("preview limit: %q", data.String())
	}
	filename, err := DownloadSMB(ctx, host, port, "Public", "hello.txt", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := os.ReadFile(filename)
	if err != nil || string(downloaded) != "hello from smb\n" {
		t.Fatalf("download: %q %v", downloaded, err)
	}
}

func TestSMBBrowserCancelsDuringHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := BrowseSMB(ctx, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "", "")
		finished <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("SMB did not connect")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("SMB handshake ignored cancellation")
	}
}

func TestSMBAccessResults(t *testing.T) {
	denied := &os.PathError{Op: "mkdir", Path: "probe", Err: &smb2.ResponseError{Code: 0xc0000022}}
	if result := smbAccessResult(denied); result == nil || *result {
		t.Fatal("SMB access denial was not recognized")
	}
	if result := smbAccessResult(os.ErrPermission); result == nil || *result {
		t.Fatal("local access denial was not recognized")
	}
	if result := smbAccessResult(context.DeadlineExceeded); result != nil {
		t.Fatal("timeout was treated as a permission denial")
	}
	if result := smbAccessResult(nil); result == nil || !*result {
		t.Fatal("successful operation was not recognized")
	}
}

type smbPartialWriter struct{}

func (smbPartialWriter) Write(p []byte) (int, error) { return 2, io.ErrShortWrite }

func TestSMBProgressCountsWrittenBytes(t *testing.T) {
	var dst bytes.Buffer
	var counts []int64
	w := &smbProgressWriter{dst: &dst, progress: func(n int64) { counts = append(counts, n) }}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("de")); err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 || counts[0] != 3 || counts[1] != 5 || dst.String() != "abcde" {
		t.Fatalf("wrong counts %v", counts)
	}
	w.dst = smbPartialWriter{}
	n, err := w.Write([]byte("abcd"))
	if n != 2 || err != io.ErrShortWrite || counts[len(counts)-1] != 7 {
		t.Fatal("partial write incorrectly counted")
	}
}
