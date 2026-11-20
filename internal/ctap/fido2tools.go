package ctap

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Tools drives the libfido2 command-line tools (fido2-token, fido2-cred, fido2-assert). The tools ask for the PIN themselves on the terminal; this
// process never sees it. Input formats are those of the tools' man pages (INPUT FORMAT / OUTPUT FORMAT).
type Tools struct {
	Dir    string // directory with the tools; empty: look them up on PATH
	Device string // a device path as fido2-token -L prints it; empty: the one key that is plugged in
	// Run starts a tool. nil: exec it, with stdin as given, stderr captured, and the terminal left to the tool (it opens /dev/tty for the PIN).
	Run func(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, err error)
	// Notify is told what the person must do ("touch your key"); nil: nobody is told.
	Notify func(string)
}

func (t *Tools) say(s string) {
	if t.Notify != nil {
		t.Notify(s)
	}
}

func (t *Tools) run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	if t.Run != nil {
		return t.Run(ctx, name, args, stdin)
	}
	bin := name
	if t.Dir != "" {
		bin = filepath.Join(t.Dir, name)
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, nil, fmt.Errorf("ctap: %s is not installed (it comes with libfido2: apt install fido2-tools, brew install libfido2): %w", name, err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Env = os.Environ()
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// device returns the key to talk to: the configured path, or the only key found.
func (t *Tools) device(ctx context.Context) (string, error) {
	if t.Device != "" {
		return t.Device, nil
	}
	out, errb, err := t.run(ctx, "fido2-token", []string{"-L"}, nil)
	if err != nil {
		return "", fmt.Errorf("ctap: fido2-token -L: %w: %s", err, strings.TrimSpace(string(errb)))
	}
	var devs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		path, _, ok := strings.Cut(line, ": ") // the path may itself contain a colon (ioreg://…)
		if !ok {
			return "", fmt.Errorf("ctap: cannot read the device list line %q", line)
		}
		devs = append(devs, path)
	}
	switch len(devs) {
	case 0:
		return "", errors.New("ctap: no security key found: plug it in (on Linux, check that your user may open /dev/hidraw*)")
	case 1:
		return devs[0], nil
	}
	return "", fmt.Errorf("ctap: %d security keys are plugged in (%s): unplug all but one, or pass the device path", len(devs), strings.Join(devs, ", "))
}

var b64 = base64.StdEncoding

// lines splits a tool's output into its non-empty lines.
func lines(out []byte) []string {
	var ls []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	return ls
}

func toolErr(tool string, err error, stderr []byte) error {
	return fmt.Errorf("ctap: %s failed: %w: %s", tool, err, strings.TrimSpace(string(stderr)))
}

// MakeCredential runs fido2-cred -M -v: the tool asks for the PIN and the key asks for a touch. Each algorithm of r is tried in order; a key that does
// not know one answers "unsupported algorithm" before it asks for anything.
func (t *Tools) MakeCredential(ctx context.Context, r MakeRequest) (*MakeResult, error) {
	dev, err := t.device(ctx)
	if err != nil {
		return nil, err
	}
	in := fmt.Sprintf("%s\n%s\n%s\n%s\n", b64.EncodeToString(r.ClientDataHash[:]), r.RPID, r.UserName, b64.EncodeToString(r.UserID))
	for _, alg := range r.Algs {
		name := map[Alg]string{ES256: "es256", EdDSA: "eddsa"}[alg]
		if name == "" {
			continue
		}
		t.say("Enter the key's PIN when asked, then touch the key when it blinks.")
		out, errb, err := t.run(ctx, "fido2-cred", []string{"-M", "-v", dev, name}, []byte(in))
		if err != nil {
			if strings.Contains(string(errb), "unsupported algorithm") {
				continue
			}
			return nil, toolErr("fido2-cred", err, errb)
		}
		ls := lines(out)
		if len(ls) < 6 {
			return nil, fmt.Errorf("ctap: fido2-cred printed %d lines, want at least 6", len(ls))
		}
		if ls[0] != b64.EncodeToString(r.ClientDataHash[:]) || ls[1] != r.RPID {
			return nil, errors.New("ctap: fido2-cred answered for another client data hash or relying party")
		}
		res := &MakeResult{Alg: alg, Format: ls[2]}
		for _, f := range []struct {
			dst *[]byte
			s   string
		}{{&res.AuthData, ls[3]}, {&res.CredentialID, ls[4]}, {&res.Signature, ls[5]}} {
			if *f.dst, err = b64.DecodeString(f.s); err != nil {
				return nil, fmt.Errorf("ctap: fido2-cred output is not base64: %w", err)
			}
		}
		if len(ls) > 6 {
			if res.X5C, err = b64.DecodeString(ls[6]); err != nil {
				return nil, fmt.Errorf("ctap: fido2-cred certificate is not base64: %w", err)
			}
		}
		if res.AuthData, err = unwrapByteString(res.AuthData); err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, ErrUnsupportedAlg
}

// GetAssertion runs fido2-assert -G -v: PIN and touch.
func (t *Tools) GetAssertion(ctx context.Context, r AssertRequest) (*AssertResult, error) {
	dev, err := t.device(ctx)
	if err != nil {
		return nil, err
	}
	in := fmt.Sprintf("%s\n%s\n%s\n", b64.EncodeToString(r.ClientDataHash[:]), r.RPID, b64.EncodeToString(r.CredentialID))
	t.say("Enter the key's PIN when asked, then touch the key when it blinks.")
	out, errb, err := t.run(ctx, "fido2-assert", []string{"-G", "-v", dev}, []byte(in))
	if err != nil {
		return nil, toolErr("fido2-assert", err, errb)
	}
	ls := lines(out)
	if len(ls) < 4 {
		return nil, fmt.Errorf("ctap: fido2-assert printed %d lines, want 4", len(ls))
	}
	if ls[0] != b64.EncodeToString(r.ClientDataHash[:]) || ls[1] != r.RPID {
		return nil, errors.New("ctap: fido2-assert answered for another client data hash or relying party")
	}
	ad, err := b64.DecodeString(ls[2])
	if err != nil {
		return nil, fmt.Errorf("ctap: fido2-assert output is not base64: %w", err)
	}
	if ad, err = unwrapByteString(ad); err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(ls[3])
	if err != nil {
		return nil, fmt.Errorf("ctap: fido2-assert output is not base64: %w", err)
	}
	return &AssertResult{AuthData: ad, Signature: sig}, nil
}
