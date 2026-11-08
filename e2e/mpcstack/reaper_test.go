package mpcstack_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ws4charlie/quorum-vault/e2e/mpcstack"
)

const helperEnv = "QV_REAPER_TEST_HELPER" // "kill": stay alive until killed; "exit": start children, clean up, exit normally

func TestMain(m *testing.M) {
	mpcstack.ReaperMain()
	os.Exit(m.Run())
}

// alive reports whether the process exists and is not a zombie.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "Z") && strings.TrimSpace(string(out)) != ""
}

// TestHelperHarness is the "test binary" of the tests below, run as a subprocess: it starts the reaper, starts children the way the harness does
// (mpcstack.Proc, which guards them), writes their pids to a file and waits to be killed (or, with "exit", stops them and ends normally).
func TestHelperHarness(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("only as a subprocess of TestKilledTestBinaryLeavesNoChild and TestNormalRunLeavesNoChild")
	}
	stop, err := mpcstack.StartReaper()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pids := []string{fmt.Sprint(mpcstack.ReaperPid())}
	var procs []*mpcstack.Proc
	for i := 0; i < 3; i++ {
		p := mpcstack.NewProc(t, fmt.Sprintf("child-%d", i), filepath.Join(dir, fmt.Sprintf("child-%d.log", i)), "/bin/sleep", nil, "300")
		p.Start(t)
		procs = append(procs, p)
		pids = append(pids, fmt.Sprint(p.Pid()))
	}
	// A child that dies on purpose and is started again: it joins the same group.
	procs[0].Kill()
	procs[0].Start(t)
	pids = append(pids, fmt.Sprint(procs[0].Pid()))
	if err := os.WriteFile(os.Getenv("QV_REAPER_TEST_PIDS"), []byte(strings.Join(pids, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "kill" {
		time.Sleep(10 * time.Minute) // killed by the parent test long before this
	}
	// "exit": a normal run. The harness stops its children (the t.Cleanup of NewProc), then the reaper is stopped as TestMain does.
	t.Cleanup(stop)
}

func runHelper(t *testing.T, mode string) (*exec.Cmd, []int) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "pids")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHarness$", "-test.v")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, "QV_REAPER_TEST_PIDS="+pidFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	var pids []int
	dl := time.Now().Add(30 * time.Second)
	for len(pids) < 5 && time.Now().Before(dl) {
		time.Sleep(50 * time.Millisecond)
		b, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pids = pids[:0]
		for _, f := range strings.Fields(string(b)) {
			n, _ := strconv.Atoi(f)
			pids = append(pids, n)
		}
	}
	if len(pids) != 5 { // the reaper, three children, the restarted one
		t.Fatalf("the helper wrote pids %v", pids)
	}
	return cmd, pids
}

func waitGone(t *testing.T, pids []int, within time.Duration) {
	t.Helper()
	dl := time.Now().Add(within)
	for {
		var left []int
		for _, p := range pids {
			if alive(p) {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(dl) {
			for _, p := range left {
				_ = syscall.Kill(p, syscall.SIGKILL)
			}
			t.Fatalf("processes %v are still running %s after the test binary ended", left, within)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestKilledTestBinaryLeavesNoChild(t *testing.T) {
	cmd, pids := runHelper(t, "kill")
	// The reaper and the three children are up (the first child was killed and replaced: its old pid is gone, the new one is up).
	for _, p := range append(pids[:1:1], pids[2:]...) {
		if !alive(p) {
			t.Fatalf("process %d should be running before the kill", p)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waitGone(t, pids, 5*time.Second)
}

func TestNormalRunLeavesNoChild(t *testing.T) {
	cmd, pids := runHelper(t, "exit")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the helper: %v", err)
	}
	waitGone(t, pids, 5*time.Second)
}
