package broker

import (
	"testing"

	"github.com/miekg/pkcs11"
)

func TestIsSoftHSMUsesWhatTheModuleReports(t *testing.T) {
	for _, c := range []struct {
		lib  pkcs11.Info
		tok  *pkcs11.TokenInfo
		want bool
	}{
		{pkcs11.Info{ManufacturerID: "SoftHSM project"}, nil, true},
		{pkcs11.Info{LibraryDescription: "Implementation of PKCS11 (softhsm)"}, nil, true},
		{pkcs11.Info{ManufacturerID: "Vendor"}, &pkcs11.TokenInfo{Model: "SoftHSM v2"}, true},
		{pkcs11.Info{ManufacturerID: "Thales"}, &pkcs11.TokenInfo{Model: "Luna"}, false},
	} {
		if got := isSoftHSM(c.lib, c.tok); got != c.want {
			t.Errorf("%+v %+v: %v", c.lib, c.tok, got)
		}
	}
}

// Both build modes: SoftHSM is refused unless QV_ENV is dev or test; an unset or odd value is production.
func TestRefuseSoftHSMInProduction(t *testing.T) {
	soft := pkcs11.Info{ManufacturerID: "SoftHSM project"}
	for env, refused := range map[string]bool{"": true, "prod": true, "production": true, "dev ": false, "DEV": false, "test": false, "tset": true} {
		t.Setenv("QV_ENV", env)
		if err := refuseSoftHSM(soft, nil, "lib.so"); (err != nil) != refused {
			t.Errorf("QV_ENV=%q: refused=%v, want %v (%v)", env, err != nil, refused, err)
		}
	}
	t.Setenv("QV_ENV", "")
	if err := refuseSoftHSM(pkcs11.Info{ManufacturerID: "Thales"}, nil, "lib.so"); err != nil {
		t.Errorf("a real HSM was refused: %v", err)
	}
}
