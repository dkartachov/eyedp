// Package session manages browser login sessions: the server-side session
// record, and the cookie and request-context plumbing around it.
package session

import (
	"context"
	"errors"
	"time"
)

// Session is a signed-in browser session.
type Session struct {
	// ID is the secret value stored in the browser's cookie. Anyone who knows
	// it is signed in as UserID.
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ErrNotFound is returned when a session does not exist or is no longer
// valid. Store implementations return it for unknown keys.
var ErrNotFound = errors.New("session: not found")

// Store persists sessions. It is a dumb key-value store: it does not check
// expiry or generate anything. Key is whatever Manager decides to index by:
// the session ID itself, or e.g. a hash of it, so that a leaked store does
// not leak usable session IDs.
type Store interface {
	Save(ctx context.Context, key string, s Session) error
	Get(ctx context.Context, key string) (Session, error)
	Delete(ctx context.Context, key string) error
}

// ---------------------------------------------------------------------------
// YOUR CODE: session lifecycle.
//
// Things to decide: how session IDs are generated (how many bytes of
// entropy, from which source, how they're encoded), what the store is keyed
// by, absolute vs idle expiry, and whether Lookup should extend a session.
//
// Rotation on login is handled by the login handler: it calls Destroy on any
// session the browser already had and then Create, so a session ID that
// existed before login is never promoted to an authenticated one (session
// fixation). Create must therefore always mint a brand new ID.
//
// Suggested reading: OWASP Session Management Cheat Sheet.
// ---------------------------------------------------------------------------

// Manager creates, validates and destroys sessions.
type Manager struct {
	store Store
	ttl   time.Duration
	now   func() time.Time
}

// NewManager returns a Manager that stores sessions in store and expires them
// ttl after creation.
func NewManager(store Store, ttl time.Duration) *Manager {
	return &Manager{store: store, ttl: ttl, now: time.Now}
}

// Create starts a new session for userID with a freshly generated ID.
func (m *Manager) Create(ctx context.Context, userID string) (Session, error) { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement Manager.Create")
}

// Lookup returns the session with the given ID. It returns ErrNotFound if the
// session does not exist or has expired.
func (m *Manager) Lookup(ctx context.Context, id string) (Session, error) { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement Manager.Lookup")
}

// Destroy ends the session with the given ID. Destroying a session that does
// not exist is not an error.
func (m *Manager) Destroy(ctx context.Context, id string) error { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement Manager.Destroy")
}
