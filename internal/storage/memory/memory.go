// Package memory provides in-memory, non-persistent implementations of the
// storage interfaces. Everything is lost when the process exits.
package memory

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/user"
)

// Users is an in-memory user.Store.
type Users struct {
	mu         sync.RWMutex
	byID       map[string]user.User
	byUsername map[string]string // username -> ID
}

var _ user.Store = (*Users)(nil)

// NewUsers returns an empty Users store.
func NewUsers() *Users {
	return &Users{
		byID:       make(map[string]user.User),
		byUsername: make(map[string]string),
	}
}

// Create implements user.Store.
func (s *Users) Create(_ context.Context, u user.User) (user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.byUsername[u.Username]; taken {
		return user.User{}, user.ErrUsernameTaken
	}
	u.ID = rand.Text()
	u.CreatedAt = time.Now().UTC()
	s.byID[u.ID] = u
	s.byUsername[u.Username] = u.ID
	return u, nil
}

// ByID implements user.Store.
func (s *Users) ByID(_ context.Context, id string) (user.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.byID[id]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return u, nil
}

// ByUsername implements user.Store.
func (s *Users) ByUsername(_ context.Context, username string) (user.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.byUsername[username]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return s.byID[id], nil
}

// Sessions is an in-memory session.Store.
type Sessions struct {
	mu    sync.RWMutex
	byKey map[string]session.Session
}

var _ session.Store = (*Sessions)(nil)

// NewSessions returns an empty Sessions store.
func NewSessions() *Sessions {
	return &Sessions{byKey: make(map[string]session.Session)}
}

// Save implements session.Store. It overwrites any session with the same key.
func (s *Sessions) Save(_ context.Context, key string, sess session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byKey[key] = sess
	return nil
}

// Get implements session.Store.
func (s *Sessions) Get(_ context.Context, key string) (session.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.byKey[key]
	if !ok {
		return session.Session{}, session.ErrNotFound
	}
	return sess, nil
}

// Delete implements session.Store. Deleting a missing key is not an error.
func (s *Sessions) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.byKey, key)
	return nil
}
