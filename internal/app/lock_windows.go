//go:build windows

package app

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func OwnerLock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "executor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	overlapped := &windows.Overlapped{}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		f.Close()
		return nil, fmt.Errorf("wscan уже запущен для этого каталога; используйте его Web-интерфейс")
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, overlapped); _ = f.Close() }, nil
}
