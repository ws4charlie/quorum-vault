package mpcstack

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// The reaper keeps a killed test binary from leaving its children behind.
//
// An end-to-end test binary spawns long-lived processes (qv-core, qv-worker, qv-gateway, qv-cosigner, mpc-party). When the binary dies without
// running its cleanups (SIGKILL, a timeout panic, the CI runner cancelling a job, a developer's kill), those processes used to live on. Linux
// has PR_SET_PDEATHSIG for this, macOS has nothing, and a signal handler cannot run on SIGKILL, so the harness uses one mechanism for both:
//
//   - At start, the test binary runs itself once more as the reaper (same executable, QV_E2E_REAPER=1; see ReaperMain), with a pipe on its standard
//     input whose other end only the test binary holds, and the reaper in a process group of its own.
//   - Every long-lived child is put into that group (Guard).
//   - When the test binary dies, the kernel closes the pipe, the reaper reads end-of-file, and kills its whole group with SIGKILL.
//
// A child that a test kills or stops on purpose, and a child it starts again, behave as before: Guard only chooses the process group.
// Nothing in a production binary is involved. If no reaper is running (a package that did not start one), Guard does nothing.

const reaperEnv = "QV_E2E_REAPER"

var (
	reaperMu   sync.Mutex
	reaperPgid int       // the reaper's process id, which is also the id of the group it leads; 0: none
	reaperPipe io.Closer // the parent's end of the pipe
	reaperCmd  *exec.Cmd
)

// ReaperMain must be the first thing a TestMain does. In the reaper process it waits for the parent to die (or to close the pipe) and then kills
// its process group; in any other process it returns at once.
func ReaperMain() {
	if os.Getenv(reaperEnv) != "1" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin) // blocks until the parent's end of the pipe is closed, which the kernel does when the parent dies
	_ = syscall.Kill(-os.Getpid(), syscall.SIGKILL)
	os.Exit(0) // not reached: the group includes this process
}

// StartReaper starts the reaper for this test binary and returns the function that ends it: call it when the tests are over, before os.Exit.
// Ending it kills whatever is still in the group; a run that cleaned up after itself has nothing left there. A failure to start it is returned
// and the tests can go on without the protection.
func StartReaper() (stop func(), err error) {
	reaperMu.Lock()
	defer reaperMu.Unlock()
	if reaperPgid != 0 {
		return func() {}, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return func() {}, fmt.Errorf("reaper: %w", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), reaperEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // a group of its own, led by the reaper: its id is the reaper's pid
	w, err := cmd.StdinPipe()
	if err != nil {
		return func() {}, fmt.Errorf("reaper: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return func() {}, fmt.Errorf("reaper: %w", err)
	}
	reaperPgid, reaperPipe, reaperCmd = cmd.Process.Pid, w, cmd
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	return func() {
		reaperMu.Lock()
		defer reaperMu.Unlock()
		if reaperPgid == 0 {
			return
		}
		_ = reaperPipe.Close()
		<-done
		reaperPgid = 0
	}, nil
}

// Guard puts a child that is about to be started into the reaper's process group. Call it on the command before Start.
func Guard(cmd *exec.Cmd) {
	reaperMu.Lock()
	defer reaperMu.Unlock()
	if reaperPgid == 0 {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid, cmd.SysProcAttr.Pgid = true, reaperPgid
}

// ReaperPid is the process id of the reaper (0: none), for the test of the reaper itself.
func ReaperPid() int {
	reaperMu.Lock()
	defer reaperMu.Unlock()
	return reaperPgid
}
