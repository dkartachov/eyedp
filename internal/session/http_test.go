package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeLooker map[string]Session

func (f fakeLooker) Lookup(_ context.Context, id string) (Session, error) {
	if id == "broken" {
		return Session{}, errors.New("store down")
	}
	s, ok := f[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func TestSetCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	SetCookie(rec, Session{ID: "abc", ExpiresAt: exp})

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName || c.Value != "abc" || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie missing security attributes: %+v", c)
	}
	if !c.Expires.Equal(exp) {
		t.Errorf("Expires = %v, want %v", c.Expires, exp)
	}
}

func TestClearCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearCookie(rec)

	c := rec.Result().Cookies()[0]
	if c.Name != CookieName || c.MaxAge >= 0 {
		t.Errorf("cookie = %+v, want %s with negative MaxAge", c, CookieName)
	}
}

func TestLoad(t *testing.T) {
	sessions := fakeLooker{"good": {ID: "good", UserID: "u1"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		cookie      string
		wantStatus  int
		wantSession bool
		wantCleared bool
	}{
		{name: "no cookie", wantStatus: http.StatusOK},
		{name: "valid session", cookie: "good", wantStatus: http.StatusOK, wantSession: true},
		{name: "unknown session", cookie: "stale", wantStatus: http.StatusOK, wantCleared: true},
		{name: "store error", cookie: "broken", wantStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotSession bool
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s, ok := FromContext(r.Context())
				gotSession = ok && s.UserID == "u1"
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: CookieName, Value: tt.cookie}) //nolint:gosec // request-side cookie; attributes are irrelevant
			}
			rec := httptest.NewRecorder()
			Load(sessions, logger, next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if gotSession != tt.wantSession {
				t.Errorf("session in context = %v, want %v", gotSession, tt.wantSession)
			}
			cleared := len(rec.Result().Cookies()) == 1 && rec.Result().Cookies()[0].MaxAge < 0
			if cleared != tt.wantCleared {
				t.Errorf("cookie cleared = %v, want %v", cleared, tt.wantCleared)
			}
		})
	}
}
