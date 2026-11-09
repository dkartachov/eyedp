package authn

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/user"
)

// The interfaces below are what the handlers need from the domain types, so
// the HTTP layer can be tested with fakes. *Authenticator, *session.Manager
// and user.Store satisfy them.
type (
	// CredentialChecker authenticates a username/password pair.
	CredentialChecker interface {
		Authenticate(ctx context.Context, username, password string) (user.User, error)
	}
	// SessionManager creates, validates and destroys sessions.
	SessionManager interface {
		Create(ctx context.Context, userID string) (session.Session, error)
		Lookup(ctx context.Context, id string) (session.Session, error)
		Destroy(ctx context.Context, id string) error
	}
	// UserGetter fetches users by ID.
	UserGetter interface {
		ByID(ctx context.Context, id string) (user.User, error)
	}
)

// maxFormBytes caps the size of a login form submission.
const maxFormBytes = 64 << 10

// Handler serves the browser-facing sign-in pages.
type Handler struct {
	Logger    *slog.Logger
	Auth      CredentialChecker
	Sessions  SessionManager
	Users     UserGetter
	Templates *template.Template // must define "login.html" and "home.html"
}

// Register adds the handler's routes to mux.
//
// The routes are wrapped in cross-origin protection: state-changing requests
// (POST) are rejected unless the browser reports them as same-origin, via
// the Sec-Fetch-Site or Origin header. That is the CSRF defence for the login
// and logout forms, so no hidden form tokens are needed. It is deliberately
// not applied globally because endpoints like /token are legitimately called
// cross-origin.
func (h *Handler) Register(mux *http.ServeMux) {
	cop := http.NewCrossOriginProtection()
	wrap := func(f http.HandlerFunc) http.Handler {
		return cop.Handler(session.Load(h.Sessions, h.Logger, f))
	}

	mux.Handle("GET /{$}", wrap(h.home))
	mux.Handle("GET /login", wrap(h.loginPage))
	mux.Handle("POST /login", wrap(h.login))
	mux.Handle("POST /logout", wrap(h.logout))
}

type loginData struct {
	Username string
	Error    string
}

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	s, ok := session.FromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	u, err := h.Users.ByID(r.Context(), s.UserID)
	if errors.Is(err, user.ErrNotFound) {
		// The account is gone but the session survived it; drop the session.
		h.endSession(w, r, s.ID)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		h.serverError(w, "look up user", err)
		return
	}

	h.render(w, http.StatusOK, "home.html", struct{ Username string }{u.Username})
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := session.FromContext(r.Context()); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.render(w, http.StatusOK, "login.html", loginData{})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.render(w, http.StatusBadRequest, "login.html", loginData{Error: "Invalid form submission."})
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if username == "" || password == "" {
		h.render(w, http.StatusBadRequest, "login.html", loginData{
			Username: username,
			Error:    "Username and password are required.",
		})
		return
	}

	u, err := h.Auth.Authenticate(r.Context(), username, password)
	if errors.Is(err, ErrInvalidCredentials) {
		h.Logger.Info("login failed", "username", username)
		h.render(w, http.StatusUnauthorized, "login.html", loginData{
			Username: username,
			Error:    "Invalid username or password.",
		})
		return
	}
	if err != nil {
		h.serverError(w, "authenticate", err)
		return
	}

	// Session fixation defence: never upgrade a session ID the browser
	// already had. Throw it away and issue a fresh one.
	if old, ok := session.FromContext(r.Context()); ok {
		if err := h.Sessions.Destroy(r.Context(), old.ID); err != nil {
			h.serverError(w, "destroy previous session", err)
			return
		}
	}

	s, err := h.Sessions.Create(r.Context(), u.ID)
	if err != nil {
		h.serverError(w, "create session", err)
		return
	}

	h.Logger.Info("login succeeded", "user_id", u.ID)
	session.SetCookie(w, s)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout ends the current session, if any. Without a valid session there is
// nothing to clear: either no cookie was sent, or Load already cleared a
// stale one.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if s, ok := session.FromContext(r.Context()); ok {
		h.endSession(w, r, s.ID)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// endSession destroys the session and clears its cookie. A failure to destroy
// is logged but not fatal: the cookie is cleared either way.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Sessions.Destroy(r.Context(), id); err != nil {
		h.Logger.Error("destroy session", "err", err)
	}
	session.ClearCookie(w)
}

// render executes the named template into a buffer first, so a template error
// produces a clean 500 instead of a half-written page.
func (h *Handler) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := h.Templates.ExecuteTemplate(&buf, name, data); err != nil {
		h.serverError(w, "render "+name, err)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	// Forbid framing to prevent clickjacking of the login form.
	hdr.Set("Content-Security-Policy", "frame-ancestors 'none'")
	hdr.Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (h *Handler) serverError(w http.ResponseWriter, msg string, err error) {
	h.Logger.Error(msg, "err", err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
