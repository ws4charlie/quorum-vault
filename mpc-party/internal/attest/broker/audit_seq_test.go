package broker

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// MaxLoadedSeq streams the log: a log of many lines is read with memory that does not grow with its size.
func TestMaxLoadedSeqStreams(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 200)
	const lines = 200000 // about 50 MB
	for i := 1; i <= lines; i++ {
		switch {
		case i == lines/2:
			fmt.Fprintf(f, `{"time":"2026-01-01T00:00:00Z","event":"allowlist_load","outcome":"loaded","seq":9,"prev":"%s"}`+"\n", pad)
		case i == lines/3:
			fmt.Fprintf(f, `{"time":"2026-01-01T00:00:00Z","event":"allowlist_load","outcome":"refused","seq":99,"prev":"%s"}`+"\n", pad)
		default:
			fmt.Fprintf(f, `{"time":"2026-01-01T00:00:00Z","event":"release","outcome":"released","party":"A","detail":"%s","prev":"%s"}`+"\n", pad, pad)
		}
	}
	f.Close()
	fi, _ := os.Stat(p)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	var peak uint64
	got, err := MaxLoadedSeq(p)
	runtime.ReadMemStats(&m1)
	if err != nil || got != 9 {
		t.Fatalf("MaxLoadedSeq = %d, %v; want 9 (a refused load does not count)", got, err)
	}
	// Total allocation is lines * one small struct; what must not happen is a result set the size of the file. Heap in use afterwards stays small.
	if peak = m1.HeapInuse; peak > uint64(fi.Size())/4 {
		t.Fatalf("heap in use %d MB after reading a %d MB log: the log is held in memory", peak>>20, fi.Size()>>20)
	}
	if _, err := MaxLoadedSeq(filepath.Join(t.TempDir(), "none")); err != nil {
		t.Fatalf("a missing log is no floor, not an error: %v", err)
	}
}
