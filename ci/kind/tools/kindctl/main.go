// Command kindctl is the kind lane's operator tool for what the repository has no operator CLI for yet (PR #112, qv-party-admin, replaces it): the admin key and the DKG.
// It runs on the host against a port-forward of party A's caller port. The admin seed stays in the gitignored work dir; only the public key goes into the party config.
//
//	kindctl adminkey -seed FILE                       makes the seed if missing, prints the public key (hex)
//	kindctl dkg -addr HOST:PORT -cert C -key K -pin SHA256HEX -seed FILE -id hot-0   prints {"keyset","public_key","address"} (JSON)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kindctl adminkey|dkg ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "adminkey":
		err = adminkey(os.Args[2:])
	case "dkg":
		err = dkg(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kindctl:", err)
		os.Exit(1)
	}
}

func loadSeed(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a 32-byte hex seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func adminkey(args []string) error {
	fs := flag.NewFlagSet("adminkey", flag.ExitOnError)
	seedF := fs.String("seed", "", "seed file")
	fs.Parse(args)
	if _, err := os.Stat(*seedF); os.IsNotExist(err) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		if err := os.WriteFile(*seedF, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return err
		}
	}
	k, err := loadSeed(*seedF)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	return nil
}

func dkg(args []string) error {
	fs := flag.NewFlagSet("dkg", flag.ExitOnError)
	addr := fs.String("addr", "", "party A caller address")
	certF := fs.String("cert", "", "client certificate (a pinned caller of A)")
	keyF := fs.String("key", "", "client key")
	pin := fs.String("pin", "", "pin of party A's certificate (sha256 of its public key, hex)")
	seedF := fs.String("seed", "", "admin seed file")
	id := fs.String("id", "hot-0", "keyset id")
	fs.Parse(args)
	adm, err := loadSeed(*seedF)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*certF, *keyF)
	if err != nil {
		return err
	}
	pins, err := wire.ParsePins([]string{*pin})
	if err != nil {
		return err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true, //nolint:gosec // the pin is the check
		VerifyPeerCertificate: wire.VerifyPinned(pins, time.Now)}
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	r, err := pb.NewMpcPartyClient(conn).DKG(ctx, &pb.DKGRequest{KeysetId: *id, Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Admin: admin.Sign(adm, "dkg", *id, time.Now())})
	if err != nil {
		return fmt.Errorf("DKG: %w", err)
	}
	pk, err := crypto.DecompressPubkey(r.RootPublicKey)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"keyset": *id, "public_key": hex.EncodeToString(crypto.FromECDSAPub(pk)), "address": crypto.PubkeyToAddress(*pk).Hex()})
}
