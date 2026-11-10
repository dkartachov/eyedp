// Package authn verifies who a user is: password login today, later MFA and
// WebAuthn. It also serves the login and logout pages.
package authn

import (
	"context"
	"errors"
	"fmt"

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
	dummyHash string
	users     UserFinder
}

// NewAuthenticator returns an Authenticator backed by users.
func NewAuthenticator(users UserFinder) *Authenticator {
	return &Authenticator{dummyHash: HashPassword("vEcgN7GGUNxn0NzI"), users: users}
}

// Authenticate returns the user identified by username if password is
// correct.
//
// It returns ErrInvalidCredentials both when the user does not exist and
// when the password is wrong, so callers cannot tell the two apart. It verifies
// against a dummy hash on user not found, so the timing is similar to a real user
// and an attacker cannot enumerate usernames by timing the response.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (user.User, error) {
	u, err := a.users.ByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			// Verify against a dummy hash to make the timing similar to a real user
			_ = VerifyPassword(password, a.dummyHash)

			return user.User{}, ErrInvalidCredentials
		}

		return user.User{}, fmt.Errorf("authn: look up user: %w", err)
	}

	err = VerifyPassword(password, u.PasswordHash)
	if err != nil {
		if errors.Is(err, ErrInvalidPassword) {
			return user.User{}, ErrInvalidCredentials
		}

		return user.User{}, fmt.Errorf("authn: verify password for user %s: %w", u.ID, err)
	}

	return u, nil
}
