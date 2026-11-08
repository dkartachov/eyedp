package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// CookieName is the name of the session cookie.
//
// The __Host- prefix makes browsers reject the cookie unless it is Secure,
// has Path=/ and no Domain, so it cannot be set by a sibling subdomain or
// over plain HTTP. Browsers treat http://localhost as secure, so local
// development still works.
const CookieName = "__Host-eyedp_session"

// SetCookie writes the session cookie for s.
func SetCookie(w http.ResponseWriter, s Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    s.ID,
		Path:     "/",
		Expires:  s.ExpiresAt,
		Secure:   true,
		HttpOnly: true,                 // not readable from JavaScript
		SameSite: http.SameSiteLaxMode, // sent on top-level navigations (OAuth redirects) but not cross-site POSTs
	})
}

// ClearCookie tells the browser to delete the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// IDFromRequest returns the session ID from r's cookie, if present.
func IDFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

type ctxKey struct{}

// NewContext returns a copy of ctx carrying s.
func NewContext(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext returns the session stored in ctx by Load, if any.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// Looker is the subset of Manager that Load needs.
type Looker interface {
	Lookup(ctx context.Context, id string) (Session, error)
}

// Load is middleware that resolves the request's session cookie and, if it
// refers to a valid session, makes the session available via FromContext.
// Requests without a valid session pass through anonymously; a stale cookie
// is cleared.
func Load(sessions Looker, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IDFromRequest(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		s, err := sessions.Lookup(r.Context(), id)
		switch {
		case errors.Is(err, ErrNotFound):
			ClearCookie(w)
			next.ServeHTTP(w, r)
		case err != nil:
			logger.Error("look up session", "err", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		default:
			next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), s)))
		}
	})
}
