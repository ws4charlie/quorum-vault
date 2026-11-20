package hsm_test

import (
	"strings"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsm/hsmtest"
)

// What SoftHSM2 reports (as of 2.6) is recognised, a real HSM's report is not, and the file name plays no part.
func TestIsSoftHSMInfo(t *testing.T) {
	soft := pkcs11.Info{ManufacturerID: "SoftHSM", LibraryDescription: "Implementation of PKCS11"}
	softTok := []pkcs11.TokenInfo{{ManufacturerID: "SoftHSM project", Model: "SoftHSM v2"}}
	cloud := pkcs11.Info{ManufacturerID: "Amazon Web Services", LibraryDescription: "CloudHSM PKCS#11"}
	luna := pkcs11.Info{ManufacturerID: "SafeNet, Inc.", LibraryDescription: "Chrysalis-ITS Cryptoki"}
	for name, c := range map[string]struct {
		lib  pkcs11.Info
		toks []pkcs11.TokenInfo
		want bool
	}{
		"softhsm library":               {soft, nil, true},
		"softhsm tokens only (wrapper)": {luna, softTok, true},
		"lower case":                    {pkcs11.Info{ManufacturerID: "softhsm"}, nil, true},
		"cloudhsm":                      {cloud, []pkcs11.TokenInfo{{ManufacturerID: "Amazon", Model: "CloudHSM"}}, false},
		"luna":                          {luna, []pkcs11.TokenInfo{{ManufacturerID: "SafeNet Inc.", Model: "Luna K7"}}, false},
		"empty report":                  {pkcs11.Info{}, nil, false},
	} {
		if got := hsm.IsSoftHSMInfo(c.lib, c.toks); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// The real SoftHSM module of this machine is detected by what it reports, and refused in production but not in development.
func TestRefuseSoftHSM(t *testing.T) {
	lib := hsmtest.Lib(t) // skips when SoftHSM is not set up (fails under QV_REQUIRE_HSM=1)
	soft, what, err := lib.IsSoftHSM()
	if err != nil || !soft {
		t.Fatalf("SoftHSM not recognised: %v %q %v", soft, what, err)
	}
	if err := hsm.RefuseSoftHSM(lib, true); err == nil || !strings.Contains(err.Error(), "refused in production") {
		t.Fatalf("production: %v", err)
	}
	if err := hsm.RefuseSoftHSM(lib, false); err != nil {
		t.Fatalf("development: %v", err)
	}
}
