// Package user holds the user domain model and the storage contract for it.
package user

import (
	"context"
	"errors"
	"time"
)

// User is an account that can sign in to the identity provider.
type User struct {
	ID       string
	Username string
	// PasswordHash is the encoded hash produced by authn.HashPassword. The
	// plaintext password is never stored.
	PasswordHash string
	CreatedAt    time.Time
}

// Errors returned by Store implementations.
var (
	ErrNotFound      = errors.New("user: not found")
	ErrUsernameTaken = errors.New("user: username already taken")
)

// Store persists users.
type Store interface {
	// Create stores u, assigning it a new ID and CreatedAt, and returns the
	// stored user. It returns ErrUsernameTaken if the username is in use.
	Create(ctx context.Context, u User) (User, error)
	// ByID returns the user with the given ID, or ErrNotFound.
	ByID(ctx context.Context, id string) (User, error)
	// ByUsername returns the user with the given username, or ErrNotFound.
	// Usernames are matched exactly (case-sensitive).
	ByUsername(ctx context.Context, username string) (User, error)
}
