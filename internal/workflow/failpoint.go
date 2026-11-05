//go:build !devauth

package workflow

// FailHook, when set (in-process tests built with -tags devauth), is called instead of exiting. It is declared in every build so
// code that sets it compiles; a production build never calls it.
var FailHook func(point string)

// Hit is a no-op in production builds: crash-testing failpoints exist only in binaries built with -tags devauth. It reads no
// environment variable, so QV_FAILPOINT in a production worker's environment does nothing.
func Hit(kind, name string) {}

// Armed is always empty in a production build.
func Armed() string { return "" }
