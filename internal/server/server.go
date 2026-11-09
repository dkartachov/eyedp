// Package server wires HTTP routes to the handlers of each feature package.
package server

import (
	"log/slog"
	"net/http"

	"github.com/dkartachov/eyedp/internal/authn"
	"github.com/dkartachov/eyedp/internal/httpx"
	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/user"
	"github.com/dkartachov/eyedp/web"
)

// Deps are the domain services the HTTP layer is built on. They are concrete
// types: interfaces belong to the handlers that consume them, not to the
// wiring.
type Deps struct {
	Logger   *slog.Logger
	Auth     *authn.Authenticator
	Sessions *session.Manager
	Users    user.Store
}

// New returns the root HTTP handler for the identity provider.
//
// As feature packages are added (oauth, oidc, keys, ...), register their
// routes here, e.g. mux.HandleFunc("GET /authorize", oauthHandler.Authorize).
func New(d Deps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealth)

	login := &authn.Handler{
		Logger:    d.Logger,
		Auth:      d.Auth,
		Sessions:  d.Sessions,
		Users:     d.Users,
		Templates: web.Templates,
	}
	login.Register(mux)

	return httpx.LogRequests(d.Logger, mux)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
