// Command quorumvault is the service entry point. T0 skeleton: config from
// env, Postgres + migrations, the "quorumvault" HSM token and GET /healthz.
// T4 replaces the wiring with the full API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ws4charlie/quorum-vault/internal/db"
	"github.com/ws4charlie/quorum-vault/internal/hsm"
)

const hsmTokenLabel = "quorumvault"

type config struct {
	DatabaseURL string
	HTTPAddr    string
	PKCS11Lib   string
	HSMPIN      string
}

func loadConfig() config {
	return config{
		DatabaseURL: getenv("DATABASE_URL", "postgres://qv:qv-dev@localhost:55432/quorumvault?sslmode=disable"),
		HTTPAddr:    getenv("QV_HTTP_ADDR", ":8080"),
		PKCS11Lib:   hsm.DefaultLibPath(),
		HSMPIN:      getenv("QV_HSM_PIN", "user-dev-1234"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(pool, tok))
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
