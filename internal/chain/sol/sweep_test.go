package sol

import "testing"

// How many deposit addresses fit in one sweep transaction (1232 bytes, one more signature and more accounts for each).
func TestMaxBatch(t *testing.T) {
	sol, tok := MaxBatch(false), MaxBatch(true)
	t.Logf("a sweep takes at most %d SOL addresses, %d token addresses (with the hot account opened and every deposit account closed)", sol, tok)
	if sol < 4 || tok < 3 || sol < tok {
		t.Fatalf("batch sizes %d, %d", sol, tok)
	}
}
