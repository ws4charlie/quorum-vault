package main

/*
#include <stdlib.h>
#include <signal.h>
static void qv_abort(void){ abort(); }
static void qv_segv(void){ volatile int *p = 0; *p = 1; }
*/
import "C"

import "errors"

// crashNow simulates failures inside the C++ side: 1 abort(), 2 NULL deref, 3 Go panic.
func crashNow(kind int) error {
	switch kind {
	case 1:
		C.qv_abort()
	case 2:
		C.qv_segv()
	case 3:
		panic("boom")
	}
	return errors.New("no-op")
}
