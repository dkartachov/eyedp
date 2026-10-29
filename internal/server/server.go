// Package server wires HTTP routes to the handlers of each feature package.
package server

import (
	"log/slog"
	"net/http"

	"github.com/dkartachov/eyedp/internal/httpx"
)

// New returns the root HTTP handler for the identity provider.
//
// As feature packages are added (oauth, oidc, keys, ...), register their
// routes here, e.g. mux.HandleFunc("GET /authorize", oauthHandler.Authorize).
func New(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealth)

	return httpx.LogRequests(logger, mux)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
