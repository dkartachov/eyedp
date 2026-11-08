// Command eyedp runs the identity provider.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dkartachov/eyedp/internal/authn"
	"github.com/dkartachov/eyedp/internal/server"
	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/storage/memory"
	"github.com/dkartachov/eyedp/internal/user"
)

// sessionTTL is how long a browser login session lasts.
const sessionTTL = 12 * time.Hour

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Getenv, os.Stdout)
	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run starts the server and blocks until ctx is cancelled or the server fails.
// Its dependencies on the process environment are passed in so that tests can
// run the fully wired server in-process.
func run(ctx context.Context, getenv func(string) string, stdout io.Writer) error {
	logger := slog.New(slog.NewTextHandler(stdout, nil))
	addr := envOr(getenv, "EYEDP_ADDR", ":8080")

	users := memory.NewUsers()
	if spec := getenv("EYEDP_DEV_USER"); spec != "" {
		if err := seedDevUser(ctx, users, spec); err != nil {
			return err
		}
		logger.Warn("seeded development user; do not use EYEDP_DEV_USER in production")
	}

	handler := server.New(server.Deps{
		Logger:   logger,
		Auth:     authn.NewAuthenticator(users),
		Sessions: session.NewManager(memory.NewSessions(), sessionTTL),
		Users:    users,
	})

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// seedDevUser creates a user from a "username:password" spec.
func seedDevUser(ctx context.Context, users user.Store, spec string) error {
	username, password, ok := strings.Cut(spec, ":")
	if !ok || username == "" || password == "" {
		return errors.New(`EYEDP_DEV_USER must be "username:password"`)
	}

	hash, err := authn.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash dev user password: %w", err)
	}
	if _, err := users.Create(ctx, user.User{Username: username, PasswordHash: hash}); err != nil {
		return fmt.Errorf("create dev user: %w", err)
	}
	return nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}
