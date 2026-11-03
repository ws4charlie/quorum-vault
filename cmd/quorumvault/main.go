// Command quorumvault is the service: Postgres + migrations, the
// "quorumvault" HSM token (HSM signer), the 2-of-3 MPC cluster on tokens
// qv-party-{1,2,3}, key registry, policy engine, approval queue, audit log,
// signing service and the HTTP API.
//
// Environment (dev-only defaults, see .env.example): DATABASE_URL,
// QV_HTTP_ADDR, QV_PKCS11_LIB, SOFTHSM2_CONF, QV_HSM_PIN, QV_DATA_DIR
// (MPC sealed shares + pre-params under $QV_DATA_DIR/mpc), SEPOLIA_RPC_URL
// (optional: fill nonce/fees, broadcast), QV_BROADCAST (default 1 when an RPC
// URL is set; 0 = sign only).
//
// `quorumvault verify-tx <raw> [sender]` decodes a raw tx offline and checks
// its recovered sender.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/api"
	"github.com/ws4charlie/quorum-vault/internal/approval"
	"github.com/ws4charlie/quorum-vault/internal/audit"
	"github.com/ws4charlie/quorum-vault/internal/chain/eth"
	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/domain"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
	"github.com/ws4charlie/quorum-vault/internal/hsmsigner"
	"github.com/ws4charlie/quorum-vault/internal/keys"
	"github.com/ws4charlie/quorum-vault/internal/mpc"
	"github.com/ws4charlie/quorum-vault/internal/policy"
	"github.com/ws4charlie/quorum-vault/internal/signer"
	"github.com/ws4charlie/quorum-vault/internal/signing"
)

const hsmTokenLabel = "quorumvault"

// writeTimeout covers the slowest call: POST /wallets for an MPC wallet runs a
// DKG (seconds; minutes on the first run while pre-params are generated).
const writeTimeout = 15 * time.Minute

type config struct {
	DatabaseURL string
	HTTPAddr    string
	PKCS11Lib   string
	HSMPIN      string
	DataDir     string
	RPCURL      string
	Broadcast   bool
}

func loadConfig() config {
	return config{
		DatabaseURL: getenv("DATABASE_URL", "postgres://qv:qv-dev@localhost:55432/quorumvault?sslmode=disable"),
		HTTPAddr:    getenv("QV_HTTP_ADDR", ":8080"),
		PKCS11Lib:   hsm.DefaultLibPath(),
		HSMPIN:      getenv("QV_HSM_PIN", "user-dev-1234"),
		DataDir:     getenv("QV_DATA_DIR", "./data"),
		RPCURL:      os.Getenv("SEPOLIA_RPC_URL"),
		Broadcast:   getenv("QV_BROADCAST", "1") != "0",
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify-tx" {
		os.Exit(verifyTx(os.Args[2:]))
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	log.Info("database ready")

	lib, err := hsm.LoadLib(cfg.PKCS11Lib)
	if err != nil {
		return err
	}
	defer lib.Close()
	tok, err := lib.OpenToken(hsmTokenLabel, cfg.HSMPIN)
	if err != nil {
		return err
	}
	defer tok.Close()
	log.Info("hsm token open", "label", tok.Label(), "lib", cfg.PKCS11Lib)

	cluster, err := mpc.NewCluster(mpc.DefaultConfig(filepath.Join(cfg.DataDir, "mpc"), cfg.HSMPIN), lib)
	if err != nil {
		return err
	}
	defer cluster.Close()
	log.Info("mpc cluster ready", "parties", cluster.PartyIDs(), "threshold", cluster.Threshold()+1)

	var rpc *eth.Client
	if cfg.RPCURL != "" {
		if rpc, err = eth.Dial(ctx, cfg.RPCURL); err != nil {
			return err
		}
		defer rpc.Close()
		log.Info("rpc connected", "chain_id", rpc.ChainID(), "broadcast", cfg.Broadcast)
	}

	aud := audit.New(pool)
	reg := keys.New(pool, aud, hsmsigner.NewGenerator(tok), signing.NewMPCGenerator(cluster, aud, log))
	pol := policy.New(pool, aud, nil)
	svc := signing.New(signing.Config{
		Pool: pool, Registry: reg, Policy: pol, Approvals: approval.New(pool, aud), Audit: aud,
		Signers: map[domain.Backend]signing.SignerFunc{
			domain.BackendHSM: func(k domain.Key) (signer.Signer, error) { return hsmsigner.New(tok, k) },
			domain.BackendMPC: func(k domain.Key) (signer.Signer, error) { return mpc.NewSigner(cluster, k) },
		},
		RPC: rpc, Broadcast: cfg.Broadcast, Logger: log,
	})
	handler := api.New(api.Config{Registry: reg, Policy: pol, Signing: svc, Audit: aud,
		Health: healthz(pool, tok), Logger: log})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
		close(errc)
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	// In-flight requests (including a running MPC ceremony) get time to finish.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

type health struct {
	OK  bool     `json:"ok"`
	DB  check    `json:"db"`
	HSM hsmCheck `json:"hsm"`
}

type check struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type hsmCheck struct {
	check
	Token string `json:"token"`
}

func healthz(pool *pgxpool.Pool, tok *hsm.Token) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var h health
		if err := pool.Ping(ctx); err != nil {
			h.DB.Error = err.Error()
		} else {
			h.DB.OK = true
		}
		h.HSM.Token = tok.Label()
		if err := tok.WithSession(ctx, hsmPing); err != nil {
			h.HSM.Error = err.Error()
		} else {
			h.HSM.OK = true
		}
		h.OK = h.DB.OK && h.HSM.OK
		w.Header().Set("Content-Type", "application/json")
		if !h.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(h)
	}
}
