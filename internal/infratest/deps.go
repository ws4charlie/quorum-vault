// Package infratest holds the Phase 2 infrastructure smoke test (Temporal +
// Redpanda). It also keeps pgregory.net/rapid in go.mod until a property test
// imports it; remove the blank import via the lead once one does.
package infratest

import _ "pgregory.net/rapid"
