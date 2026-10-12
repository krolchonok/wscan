//go:build !windows

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// OwnerLock ensures one executor process owns the configuration directory.
// The kernel releases the lock even when the process crashes.
func OwnerLock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "executor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("wscan уже запущен для этого каталога; используйте его Web-интерфейс")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
