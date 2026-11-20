package ctaptest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/ctap"
)

// ToolRun is a ctap.Tools.Run that stands in for fido2-token, fido2-cred and fido2-assert with the software key, printing exactly what the tools
// print (man fido2-cred and fido2-assert, OUTPUT FORMAT; authenticator data as one CBOR byte string, as libfido2 gives it). Lines of the tools'
// output are written from the libfido2 source; this checks our reading of them, not a real tool.
// Args seen are appended to *log.
func ToolRun(s *Soft, log *[][]string) func(context.Context, string, []string, []byte) ([]byte, []byte, error) {
	enc := base64.StdEncoding.EncodeToString
	return func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
		if log != nil {
			*log = append(*log, append([]string{name}, args...))
		}
		in := strings.Split(strings.TrimRight(string(stdin), "\n"), "\n")
		var out bytes.Buffer
		switch name {
		case "fido2-token":
			out.WriteString("ioreg://4295000001: vendor=0x1050, product=0x0407 (Simulated key)\n")
		case "fido2-cred":
			if len(in) < 4 || len(args) != 4 || args[0] != "-M" || args[1] != "-v" {
				return nil, []byte("usage"), errors.New("exit status 1")
			}
			cdh, _ := base64.StdEncoding.DecodeString(in[0])
			uid, _ := base64.StdEncoding.DecodeString(in[3])
			req := ctap.MakeRequest{RPID: in[1], UserName: in[2], UserID: uid, Algs: []ctap.Alg{map[string]ctap.Alg{"es256": ctap.ES256, "eddsa": ctap.EdDSA}[args[3]]}}
			copy(req.ClientDataHash[:], cdh)
			res, err := s.MakeCredential(ctx, req)
			if err != nil {
				return nil, []byte("fido2-cred: fido_dev_make_cred: unsupported algorithm\n"), errors.New("exit status 1")
			}
			out.WriteString(in[0] + "\n" + in[1] + "\n" + res.Format + "\n" + enc(cborBytes(res.AuthData)) + "\n" + enc(res.CredentialID) + "\n" + enc(res.Signature) + "\n")
			if len(res.X5C) > 0 {
				out.WriteString(enc(res.X5C) + "\n")
			}
		case "fido2-assert":
			if len(in) < 3 || len(args) != 3 || args[0] != "-G" || args[1] != "-v" {
				return nil, []byte("usage"), errors.New("exit status 1")
			}
			cdh, _ := base64.StdEncoding.DecodeString(in[0])
			id, _ := base64.StdEncoding.DecodeString(in[2])
			req := ctap.AssertRequest{RPID: in[1], CredentialID: id}
			copy(req.ClientDataHash[:], cdh)
			res, err := s.GetAssertion(ctx, req)
			if err != nil {
				return nil, []byte("fido2-assert: fido_dev_get_assert: no credentials\n"), errors.New("exit status 1")
			}
			out.WriteString(in[0] + "\n" + in[1] + "\n" + enc(cborBytes(res.AuthData)) + "\n" + enc(res.Signature) + "\n")
		default:
			return nil, nil, errors.New("unknown tool")
		}
		return out.Bytes(), nil, nil
	}
}
