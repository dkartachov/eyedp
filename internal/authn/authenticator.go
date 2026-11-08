// Package authn verifies who a user is: password login today, later MFA and
// WebAuthn. It also serves the login and logout pages.
package authn

import (
	"context"
	"errors"

	"github.com/dkartachov/eyedp/internal/user"
)

// ErrInvalidCredentials is returned by Authenticate when the username or
// password is wrong. It deliberately does not say which.
var ErrInvalidCredentials = errors.New("authn: invalid username or password")

// UserFinder is the subset of user.Store the Authenticator needs.
type UserFinder interface {
	ByUsername(ctx context.Context, username string) (user.User, error)
}

// ---------------------------------------------------------------------------
// YOUR CODE: the login decision.
//
// Add whatever fields you need to Authenticator (e.g. a precomputed dummy
// hash) and set them up in NewAuthenticator.
// ---------------------------------------------------------------------------

// Authenticator checks username/password credentials against the user store.
type Authenticator struct {
	users UserFinder
}

// NewAuthenticator returns an Authenticator backed by users.
func NewAuthenticator(users UserFinder) *Authenticator {
	return &Authenticator{users: users}
}

// Authenticate returns the user identified by username if password is
// correct.
//
// It must return ErrInvalidCredentials both when the user does not exist and
// when the password is wrong, so callers cannot tell the two apart. Ideally it
// also takes about the same time in both cases, so an attacker cannot
// enumerate usernames by timing the response. Any other error (e.g. the store
// failing) is returned as-is and shown to the user as a 500.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (user.User, error) { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement Authenticator.Authenticate")
}
