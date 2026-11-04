package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"qvspike/cbmpc/cbmpc"
)

var role = flag.Int("role", 2, "party number for offline commands (1 or 2)")

type backupFile struct {
	KS       string `json:"ks"`
	Label    string `json:"label"`
	Stripped string `json:"stripped_blob"`
	PVE      string `json:"pve_ciphertext"`
	Qx       string `json:"Qx"`
	Qk       string `json:"Qk"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// backup-keygen EKFILE DKFILE : create the OFFLINE recovery key pair (RSA-OAEP, used as PVE base encryption).
// backup-export KS EKFILE OUT : needs only the party's sealed state + the PUBLIC key ek; verifiable ciphertext of (x,k).
// recover BACKUP DKFILE EKFILE: needs the offline private key; rebuilds the keyset into a fresh -dir.
func backupCmd(cmd string, args []string) error {
	switch cmd {
	case "backup-keygen":
		ek, dk, err := cbmpc.PVEKeygen()
		if err != nil {
			return err
		}
		if err := os.WriteFile(args[0], ek, 0o644); err != nil {
			return err
		}
		fmt.Printf("backup-keygen: ek %d bytes, dk %d bytes (dk goes offline)\n", len(ek), len(dk))
		return os.WriteFile(args[1], dk, 0o600)
	case "backup-export":
		p, err := NewParty(*role-1, *dir)
		if err != nil {
			return err
		}
		ks, ok := p.Get(args[0])
		if !ok {
			return errors.New("no such keyset")
		}
		ek, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		stripped, x, k, Qx, Qk, err := cbmpc.KeysetSplit(ks)
		if err != nil {
			return err
		}
		label := []byte(fmt.Sprintf("qv-p5a|p%d|%s", *role, args[0]))
		ct, err := cbmpc.PVEEncrypt(ek, label, [][]byte{x, k})
		if err != nil {
			return err
		}
		if err := cbmpc.PVEVerify(ek, ct, label, [][]byte{Qx, Qk}); err != nil {
			return fmt.Errorf("PVE self-verify: %w", err)
		}
		fmt.Printf("backup-export: keyset blob %d B, stripped %d B, PVE ciphertext %d B; PVE verified against public share points without the decryption key\n", len(ks), len(stripped), len(ct))
		j, _ := json.MarshalIndent(backupFile{args[0], string(label), b64(stripped), b64(ct), b64(Qx), b64(Qk)}, "", " ")
		return os.WriteFile(args[2], j, 0o600)
	case "recover":
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var bf backupFile
		if err := json.Unmarshal(raw, &bf); err != nil {
			return err
		}
		dk, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		ek, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		if err := cbmpc.PVEVerify(ek, unb64(bf.PVE), []byte(bf.Label), [][]byte{unb64(bf.Qx), unb64(bf.Qk)}); err != nil {
			return fmt.Errorf("PVE verify: %w", err)
		}
		xs, err := cbmpc.PVEDecrypt(dk, ek, unb64(bf.PVE), []byte(bf.Label))
		if err != nil {
			return err
		}
		ks, err := cbmpc.KeysetJoin(unb64(bf.Stripped), xs[0], xs[1])
		if err != nil {
			return err
		}
		p, err := NewParty(*role-1, *dir) // fresh dir => fresh seal key (new HSM / token)
		if err != nil {
			return err
		}
		if err := p.Put(bf.KS, ks); err != nil {
			return err
		}
		fmt.Printf("recover: keyset %q rebuilt (%d B) and sealed into %s\n", bf.KS, len(ks), *dir)
		return nil
	}
	return errors.New("unknown")
}
