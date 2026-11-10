package sol

import (
	"encoding/json"
	"testing"
)

const (
	alice = "AliceDepositAddr1111111111111111111111111111" // made-up address for a test, not a secret; ggignore
	bob   = "BobDepositAddr111111111111111111111111111111" // made-up address for a test, not a secret; ggignore
	aAta  = "AliceTokenAccount1111111111111111111111111"   // made-up address for a test, not a secret; ggignore
	bAta  = "BobTokenAccount11111111111111111111111111"    // made-up address for a test, not a secret; ggignore
)

func watch() (map[string]bool, map[string]ataInfo) {
	return map[string]bool{alice: true, bob: true}, map[string]ataInfo{aAta: {alice, "TKN"}, bAta: {bob, "TKN"}}
}

func parse(t *testing.T, doc string) []string {
	t.Helper()
	var tx Transaction
	if err := json.Unmarshal([]byte(doc), &tx); err != nil {
		t.Fatal(err)
	}
	o, a := watch()
	ds, err := ParseDeposits("sol", "SIG", &tx, o, a)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range ds {
		out = append(out, d.DedupKey+" "+d.Address+" "+d.Asset+" "+d.Amount.String())
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func sys(src, dst string, lamports string) string {
	return `{"program":"system","programId":"` + SystemProgram + `","parsed":{"type":"transfer","info":{"source":"` + src + `","destination":"` + dst + `","lamports":` + lamports + `}}}`
}

func tok(typ, src, dst, extra string) string {
	return `{"program":"spl-token","programId":"` + TokenProgram + `","parsed":{"type":"` + typ + `","info":{"source":"` + src + `","destination":"` + dst + `","authority":"X"` + extra + `}}}`
}

func txDoc(err string, top string, inner string) string {
	return `{"slot":77,"meta":{"err":` + err + `,"innerInstructions":[` + inner + `]},"transaction":{"message":{"instructions":[` + top + `]},"signatures":["SIG"]}}`
}

func TestSOLTransferToAWatchedAddress(t *testing.T) {
	eq(t, parse(t, txDoc("null", sys("Other", alice, "1500000000"), "")), []string{"sol:SIG:0:- " + alice + " SOL 1500000000"})
}

func TestSOLTransferToAnUnwatchedAddressIsNothing(t *testing.T) {
	eq(t, parse(t, txDoc("null", sys("Other", "Stranger", "5"), "")), nil)
}

func TestFailedTransactionCreditsNothing(t *testing.T) {
	eq(t, parse(t, txDoc(`{"InstructionError":[0,{"Custom":1}]}`, sys("Other", alice, "1000000"), "")), nil)
}

func TestSPLTransferAndTransferCheckedToTheATA(t *testing.T) {
	top := tok("transfer", "Src", aAta, `,"amount":"2500000"`) + "," +
		tok("transferChecked", "Src", bAta, `,"mint":"M","tokenAmount":{"amount":"700","decimals":6,"uiAmount":0.0007}`)
	eq(t, parse(t, txDoc("null", top, "")), []string{
		"sol:SIG:0:- " + alice + " TKN 2500000",
		"sol:SIG:1:- " + bob + " TKN 700",
	})
}

func TestSPLTransferToAnotherTokenAccountIsNotCredited(t *testing.T) {
	eq(t, parse(t, txDoc("null", tok("transfer", "Src", "SomeOtherTokenAccount", `,"amount":"9"`), "")), nil)
}

func TestOneTransactionTouchingSeveralWatchedAddresses(t *testing.T) {
	top := sys("Other", alice, "10") + "," + sys("Other", bob, "20") + "," + sys("Other", alice, "30")
	eq(t, parse(t, txDoc("null", top, "")), []string{
		"sol:SIG:0:- " + alice + " SOL 10",
		"sol:SIG:1:- " + bob + " SOL 20",
		"sol:SIG:2:- " + alice + " SOL 30",
	})
}

// A payment made through another program (a CPI) is an inner instruction; its key says so.
func TestInnerInstructionTransferIsFound(t *testing.T) {
	inner := `{"index":3,"instructions":[` + sys("Pool", alice, "42") + `,` + tok("transfer", "PoolTok", bAta, `,"amount":"5"`) + `]}`
	top := `{"program":"unknown","programId":"SomeProgram","accounts":[],"data":"x"}`
	eq(t, parse(t, txDoc("null", top, inner)), []string{
		"sol:SIG:3:0 " + alice + " SOL 42",
		"sol:SIG:3:1 " + bob + " TKN 5",
	})
}

func TestTransferToSelfAndZeroAreIgnored(t *testing.T) {
	eq(t, parse(t, txDoc("null", sys(alice, alice, "100")+","+sys("Other", alice, "0"), "")), nil)
}

func TestOtherProgramsNamedLikeTheSystemProgramAreIgnored(t *testing.T) {
	fake := `{"program":"system","programId":"NotTheSystemProgram","parsed":{"type":"transfer","info":{"source":"X","destination":"` + alice + `","lamports":99}}}`
	eq(t, parse(t, txDoc("null", fake, "")), nil)
}
