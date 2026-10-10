package js

import (
	"context"
	"errors"
	"fmt"
	smb2 "github.com/hirochachacha/go-smb2"
	forksmb "github.com/oiweiwei/go-smb2.fork"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// SMBEntry describes a share or one entry in a remote directory.
type SMBEntry struct {
	ListingTruncated bool      `json:"listing_truncated,omitempty"`
	Name             string    `json:"name"`
	Directory        bool      `json:"directory"`
	Size             int64     `json:"size"`
	Modified         time.Time `json:"modified"`
	Read             *bool     `json:"read,omitempty"`
	Write            *bool     `json:"write,omitempty"`
	AccessError      string    `json:"access_error,omitempty"`
}

// BrowseSMB lists shares when shareName is empty, otherwise a directory.
// It uses a guest session and checks read access only; write access is unknown.
func BrowseSMB(ctx context.Context, host string, port int, shareName, remotePath string) ([]SMBEntry, error) {
	return BrowseSMBWithOptions(ctx, SMBBrowseOptions{Host: host, Port: port, Mode: "guest"}, shareName, remotePath)
}

func BrowseSMBWithOptions(ctx context.Context, o SMBBrowseOptions, shareName, remotePath string) ([]SMBEntry, error) {
	session, conn, err := openSMBBrowse(ctx, o, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer session.Logoff()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	limit := o.EntryLimit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	truncated := false
	var entries []SMBEntry
	if shareName == "" {
		names, err := session.ListSharenames()
		if err != nil {
			return nil, err
		}
		if len(names) > limit {
			names = names[:limit]
			truncated = true
		}
		for _, name := range names {
			entry := SMBEntry{Name: name, Directory: true}
			if !strings.EqualFold(name, "IPC$") {
				share, mountErr := session.Mount(name)
				if mountErr != nil {
					if smbAccessDenied(mountErr) {
						denied := false
						entry.Read = &denied
						// Write access was not probed.
					} else {
						entry.AccessError = mountErr.Error()
					}
				} else {
					entry.Read, entry.Write, entry.AccessError = probeSMBReadAccess(share)
					_ = share.Umount()
				}
			}
			entries = append(entries, entry)
		}
	} else {
		share, err := session.Mount(shareName)
		if err != nil {
			return nil, err
		}
		defer share.Umount()
		infos, limited, err := readSMBDirectory(share, cleanSMBPath(remotePath), limit)
		truncated = limited
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			entries = append(entries, SMBEntry{Name: info.Name(), Directory: info.IsDir(), Size: info.Size(), Modified: info.ModTime()})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Directory != entries[j].Directory {
			return entries[i].Directory
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	if truncated && len(entries) > 0 {
		entries[0].ListingTruncated = true
	}
	return entries, nil
}

func cleanSMBPath(value string) string {
	cleaned := strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(value, "\\", "/")), "/")
	if cleaned == "" {
		return "."
	}
	return cleaned
}

// ReadSMBFile streams a remote file to dst, optionally limiting preview size.
func ReadSMBFile(ctx context.Context, host string, port int, shareName, remotePath string, dst io.Writer, limit int64) (int64, error) {
	return ReadSMBFileWithOptions(ctx, SMBBrowseOptions{Host: host, Port: port, Mode: "guest"}, shareName, remotePath, dst, limit)
}

func ReadSMBFileWithOptions(ctx context.Context, o SMBBrowseOptions, shareName, remotePath string, dst io.Writer, limit int64) (int64, error) {
	session, conn, err := openSMBBrowse(ctx, o, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	defer session.Logoff()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	share, err := session.Mount(shareName)
	if err != nil {
		return 0, err
	}
	defer share.Umount()
	file, err := share.Open(cleanSMBPath(remotePath))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	var source io.Reader = file
	if limit > 0 {
		source = io.LimitReader(file, limit)
	}
	return io.Copy(dst, source)
}

// DownloadSMB saves to a new local file; partial downloads are removed.
func DownloadSMB(ctx context.Context, host string, port int, shareName, remotePath, directory string) (string, error) {
	return DownloadSMBWithOptions(ctx, SMBBrowseOptions{Host: host, Port: port, Mode: "guest"}, shareName, remotePath, directory)
}

func DownloadSMBWithOptions(ctx context.Context, o SMBBrowseOptions, shareName, remotePath, directory string) (string, error) {
	return DownloadSMBWithProgress(ctx, o, shareName, remotePath, directory, nil)
}

// DownloadSMBWithProgress reports bytes written locally during the transfer.
func DownloadSMBWithProgress(ctx context.Context, o SMBBrowseOptions, shareName, remotePath, directory string, progress func(int64)) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	name := path.Base(cleanSMBPath(remotePath))
	if name == "." || name == "" {
		return "", fmt.Errorf("выбери файл")
	}
	file, err := os.CreateTemp(directory, "smb-*-"+strings.ReplaceAll(name, "*", "_"))
	if err != nil {
		return "", err
	}
	destination := file.Name()
	_, err = ReadSMBFileWithOptions(ctx, o, shareName, remotePath, &smbProgressWriter{dst: file, progress: progress}, 0)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(destination)
		return "", err
	}
	return destination, nil
}

// A false permission means an explicit denial; other failures remain unknown.
func smbAccessResult(err error) *bool {
	if err == nil {
		allowed := true
		return &allowed
	}
	if smbAccessDenied(err) {
		denied := false
		return &denied
	}
	return nil
}

func probeSMBAccess(share interface {
	ReadDir(string) ([]os.FileInfo, error)
}) (*bool, *bool, string) {
	_, err := share.ReadDir(".")
	read := smbAccessResult(err)
	if err != nil && read == nil {
		return read, nil, err.Error()
	}
	return read, nil, ""
}

func smbAccessDenied(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var response *smb2.ResponseError
	// STATUS_ACCESS_DENIED is not mapped to os.ErrPermission by go-smb2.
	if errors.As(err, &response) && response.Code == 0xc0000022 {
		return true
	}
	var forkResponse *forksmb.ResponseError
	return errors.As(err, &forkResponse) && forkResponse.Code == 0xc0000022
}

// Count successful writes rather than reads, including partial writes on error.
type smbProgressWriter struct {
	dst      io.Writer
	written  int64
	progress func(int64)
}

func (w *smbProgressWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.written += int64(n)
	if w.progress != nil {
		w.progress(w.written)
	}
	return n, err
}
