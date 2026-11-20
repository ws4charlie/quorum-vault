package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// readDKGAuth reads the admin authorization of the DKG this step is about to ask the parties for. The file is a v2 request signed by the admins
// (`qv-party-admin request -op dkg -keyset ID -scheme ...`, then `sign` by each): it is refused here when it is for another keyset, another scheme
// or curve than the call this tool makes, or is expired; the parties check the signatures and the quorum themselves. An old v1 file (`qv-keysets
// party-auth`) is still read, for parties that accept v1 during the roll-over.
func readDKGAuth(path, keyset string, scheme pb.Scheme, curve pb.Curve) (*pb.AdminAuth, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch admin.FileVersion(raw) {
	case 2:
		r, err := admin.ParseRequest(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if r.Op != admin.OpDKG || r.Keyset != keyset {
			return nil, fmt.Errorf("%s is for %s of keyset %q, this step needs dkg of %q", path, r.Op, r.Keyset, keyset)
		}
		if err := r.CheckBody(&pb.DKGRequest{KeysetId: keyset, Scheme: scheme, Curve: curve}); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if time.Now().After(time.Unix(r.ExpiresUnix, 0)) {
			return nil, fmt.Errorf("%s expired at %s: make a new request and have the admins sign it", path, time.Unix(r.ExpiresUnix, 0).Format(time.RFC3339))
		}
		if len(r.Signatures) == 0 {
			return nil, fmt.Errorf("%s has no signatures: the admins sign it with `qv-party-admin sign`", path)
		}
		return r.Auth()
	case 1:
		f, err := admin.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if f.Op != admin.OpDKG || f.Keyset != keyset {
			return nil, fmt.Errorf("%s is for %s of keyset %q, this step needs dkg of %q", path, f.Op, f.Keyset, keyset)
		}
		return f.Auth()
	}
	return nil, fmt.Errorf("%s is not an admin authorisation file", path)
}
