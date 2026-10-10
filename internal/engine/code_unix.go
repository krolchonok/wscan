//go:build unix

package engine

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the code: interpreter in its own process group
// so a timeout kills it AND anything it spawned (e.g. "sleep 5" from a
// shell script), not just the direct child. Without this, exec.CommandContext
// only kills the direct child on timeout, and Cmd.Wait() still blocks until
// the stdout/stderr pipes close — which stays open as long as any
// descendant process inherited them, so a forked grandchild can keep
// execCode blocked well past the configured timeout.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the whole process group, not just cmd.Process.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
