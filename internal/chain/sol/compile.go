package sol

import "github.com/ws4charlie/quorum-vault/internal/chain/sol/solmsg"

// Ixs turns a decoded message back into instructions, with the signer and writable flags its header gives each account.
func (m *Message) Ixs() []solmsg.Ix {
	out := make([]solmsg.Ix, 0, len(m.Instructions))
	for _, in := range m.Instructions {
		x := solmsg.Ix{Program: in.Program, Data: append([]byte(nil), in.Data...)}
		for j, ai := range in.AcctIdx {
			x.Accts = append(x.Accts, solmsg.Meta{Key: in.Accts[j], Signer: m.IsSigner(ai), Writable: m.IsWritable(ai)})
		}
		out = append(out, x)
	}
	return out
}
