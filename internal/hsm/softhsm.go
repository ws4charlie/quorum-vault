package hsm

import (
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// IsSoftHSMInfo says whether what a PKCS#11 module reports about itself is SoftHSM: the word "softhsm" (any case) in the library's
// manufacturer or description (C_GetInfo; SoftHSM2 says manufacturer "SoftHSM", description "Implementation of PKCS11") or in a token's
// manufacturer or model (C_GetTokenInfo; SoftHSM2: manufacturer "SoftHSM project", model "SoftHSM v2"). It looks at what the module
// says, not at the file name, so a renamed copy is still found.
func IsSoftHSMInfo(lib pkcs11.Info, tokens []pkcs11.TokenInfo) bool {
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), "softhsm") }
	if has(lib.ManufacturerID) || has(lib.LibraryDescription) {
		return true
	}
	for _, t := range tokens {
		if has(t.ManufacturerID) || has(t.Model) {
			return true
		}
	}
	return false
}

// IsSoftHSM asks the loaded module (C_GetInfo and the tokens of its present slots) whether it is SoftHSM, and returns what it reported.
func (l *Lib) IsSoftHSM() (bool, string, error) {
	info, err := l.ctx.GetInfo()
	if err != nil {
		return false, "", fmt.Errorf("hsm: C_GetInfo: %w", err)
	}
	var toks []pkcs11.TokenInfo
	if slots, err := l.ctx.GetSlotList(true); err == nil {
		for _, s := range slots {
			if ti, err := l.ctx.GetTokenInfo(s); err == nil {
				toks = append(toks, ti)
			}
		}
	}
	return IsSoftHSMInfo(info, toks), fmt.Sprintf("manufacturer %q, description %q", strings.TrimSpace(info.ManufacturerID), strings.TrimSpace(info.LibraryDescription)), nil
}

// RefuseSoftHSM is the production guard of a service that opens a PKCS#11 module: SoftHSM keeps its keys in files on the host that runs the
// service, so in production (production is true) it is refused with a message that says why. Development, tests and the -dev images
// (QV_ENV=dev or test: production is false) are not affected.
func RefuseSoftHSM(l *Lib, production bool) error {
	if !production {
		return nil
	}
	soft, what, err := l.IsSoftHSM()
	if err != nil {
		return err
	}
	if soft {
		return fmt.Errorf("hsm: the PKCS#11 module %s is SoftHSM (%s): refused in production, SoftHSM is for development and tests only; use a real HSM, or set QV_ENV=dev on a development machine", l.path, what)
	}
	return nil
}
