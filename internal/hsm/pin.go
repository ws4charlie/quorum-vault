package hsm

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Where a long-running service gets its token PIN. The same rule as the party's pin_file (mpc-party/internal/server/sealer_pkcs11.go, another Go
// module that keeps its own copy: the two table tests, TestPINFileModes and TestPINFileThroughSymlink, are identical on purpose, keep them so).
const (
	PINFileEnv = "QV_HSM_PIN_FILE" // the file that holds the PIN: the form for production
	PINEnv     = "QV_HSM_PIN"      // the PIN itself: development and tests only
)

// ReadPIN takes the token PIN from an environment variable or from a file that only its owner, or its owner and one group, can read.
//
// The file's mode must have no world bit and no group write or execute bit. Group READ is accepted (0440, 0640): a Kubernetes Secret volume
// mounted for a non-root user with fsGroup is owned by root and readable through the group, and the pod's group is the only one that sees
// it. The log line says which mode was accepted. Anything else is refused: 0400 and 0600 as before, but not 0660, 0644, 0444, 0750, 0604.
// A trailing newline is trimmed. The PIN is never part of an error or a log line.
func ReadPIN(env, file string) (string, error) {
	switch {
	case env != "" && file != "":
		return "", errors.New("hsm: set exactly one of the PIN environment variable and the PIN file")
	case env != "":
		v := os.Getenv(env)
		if v == "" {
			return "", fmt.Errorf("hsm: environment variable %s is empty or unset", env)
		}
		return v, nil
	case file != "":
		fi, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("hsm: PIN file: %w", err)
		}
		perm := fi.Mode().Perm()
		if err := checkPINFileMode(file, perm); err != nil {
			return "", err
		}
		if perm&0o040 != 0 {
			slog.Default().Info("hsm: PIN file is group-readable and accepted (no group write or execute, no world access): expected for a Kubernetes Secret volume with fsGroup", "file", file, "mode", fmt.Sprintf("%04o", uint32(perm)))
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("hsm: PIN file: %w", err)
		}
		pin := strings.TrimRight(string(b), "\r\n")
		for i := range b { // the file buffer; the string copy lives as long as the PKCS#11 wrapper needs a string
			b[i] = 0
		}
		if pin == "" {
			return "", errors.New("hsm: PIN file is empty")
		}
		return pin, nil
	}
	return "", errors.New("hsm: no PIN source: set " + PINFileEnv)
}

// checkPINFileMode is the mode rule for the PIN file: no world bit, no group write, no group execute.
func checkPINFileMode(file string, perm os.FileMode) error {
	if perm&0o007 != 0 {
		return fmt.Errorf("hsm: PIN file %s has mode %04o: others must have no access (chmod 0400, or 0440 for a group-readable Secret volume)", file, uint32(perm))
	}
	if perm&0o030 != 0 {
		return fmt.Errorf("hsm: PIN file %s has mode %04o: the group may read it (0440) but not write or execute it", file, uint32(perm))
	}
	return nil
}

// ServicePIN is the PIN of a long-running service (qv-gateway), read once at start: from the file named by QV_HSM_PIN_FILE.
// The environment form QV_HSM_PIN works only when QV_ENV is dev or test; with QV_ENV unset or anything else it is an error that names the file
// option (an environment is visible to every process listing of the same user, is inherited by children and lands in crash dumps).
// Both set is an error. A PIN read from the environment is removed from the process's own environment after the read.
func ServicePIN() (string, error) {
	file, env := os.Getenv(PINFileEnv), os.Getenv(PINEnv)
	if env != "" && file != "" {
		return "", fmt.Errorf("hsm: both %s and %s are set: use only %s", PINEnv, PINFileEnv, PINFileEnv)
	}
	if env != "" {
		if productionEnv() {
			return "", fmt.Errorf("hsm: %s is refused in production (QV_ENV is not dev or test): an environment variable is visible in process listings, inherited by children and written to crash dumps; put the PIN in a file and set %s", PINEnv, PINFileEnv)
		}
		pin, err := ReadPIN(PINEnv, "")
		os.Unsetenv(PINEnv)
		return pin, err
	}
	if file == "" {
		return "", fmt.Errorf("hsm: no PIN: set %s to a file that holds the token PIN (mode 0400, or 0440 for a Secret volume)", PINFileEnv)
	}
	return ReadPIN("", file)
}

// productionEnv: QV_ENV unset, or anything but dev or test, is production (the rule every other service uses: a typo cannot loosen anything).
func productionEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QV_ENV"))) {
	case "dev", "test":
		return false
	}
	return true
}
