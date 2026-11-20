package server

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/miekg/pkcs11"
)

// ReadPIN takes the token PIN from an environment variable or from a file that only its owner, or its owner and one group, can read.
// It never comes from the JSON config.
//
// The file's mode must have no world bit and no group write or execute bit. Group READ is accepted (0440, 0640): a Kubernetes Secret volume
// mounted for a non-root user with fsGroup is owned by root and readable through the group, and the pod's group is the only one that sees
// it. The log line says which mode was accepted. Anything else is refused: 0400 and 0600 as before, but not 0660, 0644, 0444, 0750, 0604.
func ReadPIN(env, file string) (string, error) {
	switch {
	case env != "" && file != "":
		return "", errors.New("sealer: set exactly one of pin_env and pin_file")
	case env != "":
		v := os.Getenv(env)
		if v == "" {
			return "", fmt.Errorf("sealer: environment variable %s (pin_env) is empty or unset", env)
		}
		return v, nil
	case file != "":
		fi, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("sealer: pin_file: %w", err)
		}
		perm := fi.Mode().Perm()
		if err := checkPINFileMode(file, perm); err != nil {
			return "", err
		}
		if perm&0o040 != 0 {
			slog.Default().Info("sealer: pin_file is group-readable and accepted (no group write or execute, no world access): expected for a Kubernetes Secret volume with fsGroup", "file", file, "mode", fmt.Sprintf("%04o", uint32(perm)))
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("sealer: pin_file: %w", err)
		}
		pin := strings.TrimRight(string(b), "\r\n")
		if pin == "" {
			return "", errors.New("sealer: pin_file is empty")
		}
		return pin, nil
	}
	return "", errors.New("sealer: pkcs11 needs pin_env or pin_file")
}

// checkPINFileMode is the mode rule for pin_file: no world bit, no group write, no group execute.
func checkPINFileMode(file string, perm os.FileMode) error {
	if perm&0o007 != 0 {
		return fmt.Errorf("sealer: pin_file %s has mode %04o: others must have no access (chmod 0400, or 0440 for a group-readable Secret volume)", file, uint32(perm))
	}
	if perm&0o030 != 0 {
		return fmt.Errorf("sealer: pin_file %s has mode %04o: the group may read it (0440) but not write or execute it", file, uint32(perm))
	}
	return nil
}

// productionEnv: QV_ENV unset, or anything but dev or test, is production (the rule every other service uses: a typo cannot loosen anything).
func productionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV"))) {
	case "dev", "test":
		return false
	}
	return true
}

// isSoftHSM says whether a PKCS#11 module is SoftHSM, from what the module itself reports and not from its file name (a copy named
// libcloudhsm.so is still SoftHSM): the library's manufacturer or description (C_GetInfo), or the token's manufacturer or model
// (C_GetTokenInfo; SoftHSM2 reports manufacturer "SoftHSM project", model "SoftHSM v2"). The match is on the word "softhsm", ignoring case.
func isSoftHSM(lib pkcs11.Info, tok *pkcs11.TokenInfo) bool {
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), "softhsm") }
	if has(lib.ManufacturerID) || has(lib.LibraryDescription) {
		return true
	}
	return tok != nil && (has(tok.ManufacturerID) || has(tok.Model))
}

// refuseSoftHSM is the production guard: SoftHSM keeps the key in a file next to the data it protects, so sealing under it in production
// would be sealing under nothing. In production (QV_ENV unset, or not dev or test) a SoftHSM module stops the start; development, tests and the
// -dev images (which set QV_ENV=dev) are not affected.
func refuseSoftHSM(lib pkcs11.Info, tok *pkcs11.TokenInfo, libPath string) error {
	if productionEnv() && isSoftHSM(lib, tok) {
		return fmt.Errorf("sealer pkcs11: %s is SoftHSM (reported by the module: manufacturer %q, description %q): refused in production, it is for development and tests only; use a real HSM, or set QV_ENV=dev on a development machine",
			libPath, strings.TrimSpace(lib.ManufacturerID), strings.TrimSpace(lib.LibraryDescription))
	}
	return nil
}

func defaultPKCS11Lib() string {
	if p := os.Getenv("QV_PKCS11_LIB"); p != "" {
		return p
	}
	var c []string
	if runtime.GOOS == "darwin" {
		c = []string{"/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	} else {
		c = []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"}
	}
	for _, p := range c {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return c[0]
}
