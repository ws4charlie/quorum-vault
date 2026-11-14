package sol

import "github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"

// The names of package solmsg (addresses, program ids, the message compiler and the instructions custody builds) are also this package's: solmsg has no
// network client, so the offline cold signer can use it, and everything else keeps saying sol.X.

const (
	SystemProgram           = solmsg.SystemProgram
	TokenProgram            = solmsg.TokenProgram
	AssociatedTokenProg     = solmsg.AssociatedTokenProg
	ComputeBudgetProgram    = solmsg.ComputeBudgetProgram
	SysvarRecentBlockhashes = solmsg.SysvarRecentBlockhashes
	SysvarRent              = solmsg.SysvarRent
	NonceAccountSize        = solmsg.NonceAccountSize
	DefaultNonceRent        = solmsg.DefaultNonceRent
)

type (
	Meta = solmsg.Meta
	Ix   = solmsg.Ix
)

func Address(pub [32]byte) string                      { return solmsg.Address(pub) }
func ParseAddress(s string) ([32]byte, error)          { return solmsg.ParseAddress(s) }
func ATA(owner, mint [32]byte) ([32]byte, error)       { return solmsg.ATA(owner, mint) }
func NonceSeed(i int) string                           { return solmsg.NonceSeed(i) }
func NonceAddress(hot [32]byte, i int) [32]byte        { return solmsg.NonceAddress(hot, i) }
func AdvanceNonceData() []byte                         { return solmsg.AdvanceNonceData() }
func InitNonceData(authority [32]byte) []byte          { return solmsg.InitNonceData(authority) }
func onCurve(b []byte) bool                            { return solmsg.OnCurve(b) }
func compactU16(n int) []byte                          { return solmsg.CompactU16(n) }
func mustAddr(s string) [32]byte                       { return solmsg.MustAddr(s) }
func SetLimitIx(n uint32) Ix                           { return solmsg.SetLimitIx(n) }
func SetPriceIx(microLamports uint64) Ix               { return solmsg.SetPriceIx(microLamports) }
func AdvanceNonceIx(nonce, authority [32]byte) Ix      { return solmsg.AdvanceNonceIx(nonce, authority) }
func TransferIx(from, to [32]byte, lamports uint64) Ix { return solmsg.TransferIx(from, to, lamports) }
func CheckedTransferIx(src, mint, dst, authority [32]byte, amount uint64, decimals uint8) Ix {
	return solmsg.CheckedTransferIx(src, mint, dst, authority, amount, decimals)
}
func CreateATAIx(payer, ata, owner, mint [32]byte) Ix {
	return solmsg.CreateATAIx(payer, ata, owner, mint)
}
func CloseAccountIx(acct, rentTo, owner [32]byte) Ix {
	return solmsg.CloseAccountIx(acct, rentTo, owner)
}
func CreateNonceIxs(hot [32]byte, i int, lamports uint64) []Ix {
	return solmsg.CreateNonceIxs(hot, i, lamports)
}
func CreateWithSeedData(base [32]byte, seed string, lamports, space uint64) []byte {
	return solmsg.CreateWithSeedData(base, seed, lamports, space)
}
func Compile(payer, blockhash [32]byte, ixs ...Ix) []byte {
	return solmsg.Compile(payer, blockhash, ixs...)
}
