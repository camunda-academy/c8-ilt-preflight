//go:build !windows

package launcher

import (
	"os/exec"
	"syscall"
)

// On macOS/Linux the equivalent gap to Windows' orphaned-grandchild problem
// (see procgroup_windows.go) is Go's default kill-on-timeout signaling only
// the one process os/exec tracks -- not any children run.sh spawned via `mvn`/
// `dotnet`/`pip`/`npm`. Setpgid makes the started process its own process
// group leader; every child it forks inherits that same group unless it
// explicitly opts out, so signaling the group (a negative PID) reaches the
// whole tree in one call.
func configureSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// newProcessTreeKiller returns a kill function that signals the whole process
// group Setpgid created above, and a no-op cleanup -- there is no separate
// handle to release the way Windows' Job Object needs.
func newProcessTreeKiller(cmd *exec.Cmd) (kill func() error, cleanup func()) {
	kill = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return kill, func() {}
}
