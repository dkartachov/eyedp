package authn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/user"
	"github.com/dkartachov/eyedp/web"
)

// These tests cover the HTTP plumbing only. The domain logic (Authenticator,
// session.Manager) is replaced with fakes.

var alice = user.User{ID: "u-alice", Username: "alice"}

type fakeAuth struct{ err error }

func (f fakeAuth) Authenticate(_ context.Context, username, password string) (user.User, error) {
	if f.err != nil {
		return user.User{}, f.err
	}
	if username == "alice" && password == "secret" {
		return alice, nil
	}
	return user.User{}, ErrInvalidCredentials
}

type fakeSessions struct {
	byID      map[string]session.Session
	n         int
	destroyed []string
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{byID: make(map[string]session.Session)}
}

func (f *fakeSessions) Create(_ context.Context, userID string) (session.Session, error) {
	f.n++
	s := session.Session{ID: "sess-" + strconv.Itoa(f.n), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}
	f.byID[s.ID] = s
	return s, nil
}

func (f *fakeSessions) Lookup(_ context.Context, id string) (session.Session, error) {
	s, ok := f.byID[id]
	if !ok {
		return session.Session{}, session.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) Destroy(_ context.Context, id string) error {
	delete(f.byID, id)
	f.destroyed = append(f.destroyed, id)
	return nil
}

type fakeUsers map[string]user.User

func (f fakeUsers) ByID(_ context.Context, id string) (user.User, error) {
	u, ok := f[id]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return u, nil
}

func newTestMux(auth CredentialChecker, sessions SessionManager) *http.ServeMux {
	h := &Handler{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth:      auth,
		Sessions:  sessions,
		Users:     fakeUsers{alice.ID: alice},
		Templates: web.Templates,
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func do(t *testing.T, h http.Handler, method, target string, form url.Values, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(t.Context(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.CookieName, Value: cookie}) //nolint:gosec // request-side cookie; attributes are irrelevant
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

func TestLoginPage(t *testing.T) {
	sessions := newFakeSessions()
	mux := newTestMux(fakeAuth{}, sessions)

	rec := do(t, mux, http.MethodGet, "/login", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<form method="post" action="/login">`) {
		t.Error("login form not rendered")
	}
	for k, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	// Already signed in: bounce to home.
	s, _ := sessions.Create(t.Context(), alice.ID)
	rec = do(t, mux, http.MethodGet, "/login", nil, s.ID)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Errorf("signed-in GET /login = %d %q, want 303 /", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name       string
		auth       fakeAuth
		form       url.Values
		wantStatus int
		wantBody   string
	}{
		{
			name:       "success",
			form:       url.Values{"username": {"alice"}, "password": {"secret"}},
			wantStatus: http.StatusSeeOther,
		},
		{
			name:       "wrong password",
			form:       url.Values{"username": {"alice"}, "password": {"nope"}},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Invalid username or password.",
		},
		{
			name:       "missing fields",
			form:       url.Values{"username": {"alice"}},
			wantStatus: http.StatusBadRequest,
			wantBody:   "Username and password are required.",
		},
		{
			name:       "authenticator error",
			auth:       fakeAuth{err: errors.New("db down")},
			form:       url.Values{"username": {"alice"}, "password": {"secret"}},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := newTestMux(tt.auth, newFakeSessions())
			rec := do(t, mux, http.MethodPost, "/login", tt.form, "")

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body missing %q", tt.wantBody)
			}
			gotCookie := sessionCookie(rec) != nil
			if wantCookie := tt.wantStatus == http.StatusSeeOther; gotCookie != wantCookie {
				t.Errorf("session cookie set = %v, want %v", gotCookie, wantCookie)
			}
		})
	}
}

func TestLoginRotatesExistingSession(t *testing.T) {
	sessions := newFakeSessions()
	mux := newTestMux(fakeAuth{}, sessions)
	old, _ := sessions.Create(t.Context(), "someone-else")

	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	rec := do(t, mux, http.MethodPost, "/login", form, old.ID)

	c := sessionCookie(rec)
	if c == nil || c.Value == old.ID {
		t.Fatalf("login did not issue a new session ID (cookie %+v)", c)
	}
	if _, err := sessions.Lookup(t.Context(), old.ID); !errors.Is(err, session.ErrNotFound) {
		t.Error("previous session was not destroyed")
	}
}

func TestLoginRejectsCrossOriginPost(t *testing.T) {
	mux := newTestMux(fakeAuth{}, newFakeSessions())

	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestHome(t *testing.T) {
	sessions := newFakeSessions()
	mux := newTestMux(fakeAuth{}, sessions)

	rec := do(t, mux, http.MethodGet, "/", nil, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous GET / = %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}

	s, _ := sessions.Create(t.Context(), alice.ID)
	rec = do(t, mux, http.MethodGet, "/", nil, s.ID)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Errorf("signed-in GET / = %d, body %q", rec.Code, rec.Body)
	}

	// Session pointing at a deleted user is ended.
	orphan, _ := sessions.Create(t.Context(), "deleted-user")
	rec = do(t, mux, http.MethodGet, "/", nil, orphan.ID)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("orphaned session GET / = %d, want 303", rec.Code)
	}
	if _, err := sessions.Lookup(t.Context(), orphan.ID); err == nil {
		t.Error("orphaned session was not destroyed")
	}
}

func TestLogout(t *testing.T) {
	sessions := newFakeSessions()
	mux := newTestMux(fakeAuth{}, sessions)
	s, _ := sessions.Create(t.Context(), alice.ID)

	rec := do(t, mux, http.MethodPost, "/logout", url.Values{}, s.ID)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("POST /logout = %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	if c := sessionCookie(rec); c == nil || c.MaxAge >= 0 {
		t.Errorf("session cookie not cleared: %+v", c)
	}
	if n := len(rec.Result().Cookies()); n != 1 {
		t.Errorf("got %d Set-Cookie headers, want 1", n)
	}
	if _, err := sessions.Lookup(t.Context(), s.ID); err == nil {
		t.Error("session was not destroyed")
	}
}

func TestLogoutStaleCookie(t *testing.T) {
	mux := newTestMux(fakeAuth{}, newFakeSessions())

	rec := do(t, mux, http.MethodPost, "/logout", url.Values{}, "stale")

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("POST /logout = %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	if n := len(rec.Result().Cookies()); n != 1 {
		t.Errorf("got %d Set-Cookie headers, want 1", n)
	}
	if c := sessionCookie(rec); c == nil || c.MaxAge >= 0 {
		t.Errorf("stale session cookie not cleared: %+v", c)
	}
}
