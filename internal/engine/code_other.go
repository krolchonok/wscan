//go:build !unix

package engine

import "os/exec"

// configureProcessGroup is a no-op outside unix: Windows process trees need
// a different mechanism (job objects) this scanner does not yet set up, so
// a timeout here only kills the direct interpreter process, not whatever it
// may have spawned. Cmd.WaitDelay (set in code.go) still bounds how long
// execCode can block regardless.
func configureProcessGroup(cmd *exec.Cmd) {}
