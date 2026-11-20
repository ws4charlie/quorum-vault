// Command kindctl is the kind lane's operator tool for what the repository has no operator CLI for yet (PR #112, qv-party-admin, replaces it): the admin key and the DKG.
// It runs on the host against a port-forward of party A's caller port. The admin seed stays in the gitignored work dir; only the public key goes into the party config.
//
//	kindctl adminkey -seed FILE                       makes the seed if missing, prints the public key (hex)
//	kindctl dkg  -addr HOST:PORT -cert C -key K -pin SHA256HEX -seed FILE -id ID -scheme ecdsa-2of3|hd   prints {"keyset","public_key","address"} (JSON)
//	kindctl xpub -addr HOST:PORT -cert C -key K -pin SHA256HEX -id ID                                      prints the regtest account xpub of an hd keyset
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ws4charlie/quorum-vault/internal/mpcsigner"
	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	wire "github.com/ws4charlie/quorum-vault/mpc-party/api/cosigner"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kindctl adminkey|dkg|xpub ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "adminkey":
		err = adminkey(os.Args[2:])
	case "dkg":
		err = dkg(os.Args[2:])
	case "xpub":
		err = xpub(os.Args[2:])
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

// connect dials party A's caller port with the pinned gateway-party certificate.
func connect(fs *flag.FlagSet, args []string) (pb.MpcPartyClient, func(), *string, *string, error) {
	addr := fs.String("addr", "", "party A caller address")
	certF := fs.String("cert", "", "client certificate (a pinned caller of A)")
	keyF := fs.String("key", "", "client key")
	pin := fs.String("pin", "", "pin of party A's certificate (sha256 of its public key, hex)")
	seedF := fs.String("seed", "", "admin seed file")
	id := fs.String("id", "hot-0", "keyset id")
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, nil, err
	}
	pair, err := tls.LoadX509KeyPair(*certF, *keyF)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pins, err := wire.ParsePins([]string{*pin})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true, //nolint:gosec // the pin is the check
		VerifyPeerCertificate: wire.VerifyPinned(pins, time.Now)}
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pb.NewMpcPartyClient(conn), func() { conn.Close() }, id, seedF, nil
}

// dkg makes a keyset. ecdsa-2of3 is an EVM hot shard (its root key is the hot key: the e2e suite's 3-party mode); hd is the Bitcoin key tree (the xpub comes from `xpub`).
func dkg(args []string) error {
	fs := flag.NewFlagSet("dkg", flag.ExitOnError)
	scheme := fs.String("scheme", "ecdsa-2of3", "ecdsa-2of3 or hd")
	cl, closeFn, id, seedF, err := connect(fs, args)
	if err != nil {
		return err
	}
	defer closeFn()
	adm, err := loadSeed(*seedF)
	if err != nil {
		return err
	}
	req := &pb.DKGRequest{KeysetId: *id, Admin: admin.Sign(adm, "dkg", *id, time.Now())}
	switch *scheme {
	case "ecdsa-2of3":
		req.Scheme = pb.Scheme_SCHEME_ECDSA_2OF3
	case "hd":
		req.Curve = pb.Curve_CURVE_SECP256K1
	default:
		return fmt.Errorf("-scheme %q", *scheme)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	// A keyset that already exists is not made again: a run that lost its reply (the key made, the result never written) would get AlreadyExists for ever. The party knows the keyset
	// and its public key, so the result is rebuilt from its status.
	if done, err := existing(ctx, cl, *id); err != nil || done != nil {
		if err != nil {
			return err
		}
		return printResult(*id, done.PublicKey)
	}
	r, err := cl.DKG(ctx, req)
	if status.Code(err) == codes.AlreadyExists { // made between the status and the call (or by a run whose reply was lost)
		if done, e := existing(ctx, cl, *id); e == nil && done != nil {
			return printResult(*id, done.PublicKey)
		}
	}
	if err != nil {
		return fmt.Errorf("DKG: %w", err)
	}
	return printResult(*id, r.RootPublicKey)
}

// existing is the status of keyset id at party A when it exists and is resolved; nil when there is none yet. An existing keyset that is not resolved is an error (the caller retries).
func existing(ctx context.Context, cl pb.MpcPartyClient, id string) (*pb.KeysetStatus, error) {
	h, err := cl.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, fmt.Errorf("Health: %w", err)
	}
	for _, k := range h.Keysets {
		if k.KeysetId == id && k.Generation != 0 {
			if !k.Resolved {
				return nil, fmt.Errorf("keyset %q exists but is not resolved yet", id)
			}
			return k, nil
		}
	}
	return nil, nil
}

// printResult prints the public result of a DKG. A keyset without a group public key (an HD keyset's status has none) prints the id only: the lane reads its xpub with `xpub`.
func printResult(id string, compressed []byte) error {
	out := map[string]string{"keyset": id}
	if len(compressed) != 0 {
		pk, err := crypto.DecompressPubkey(compressed)
		if err != nil {
			return err
		}
		out["public_key"], out["address"] = hex.EncodeToString(crypto.FromECDSAPub(pk)), crypto.PubkeyToAddress(*pk).Hex()
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// xpub prints the regtest account xpub of an HD keyset (public values only).
func xpub(args []string) error {
	cl, closeFn, id, _, err := connect(flag.NewFlagSet("xpub", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	x, err := mpcsigner.AccountXpub(ctx, cl, *id, "regtest")
	if err != nil {
		return err
	}
	fmt.Println(x)
	return nil
}
