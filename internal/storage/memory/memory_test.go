package memory

import (
	"errors"
	"testing"

	"github.com/dkartachov/eyedp/internal/session"
	"github.com/dkartachov/eyedp/internal/user"
)

func TestUsers(t *testing.T) {
	ctx := t.Context()
	s := NewUsers()

	created, err := s.Create(ctx, user.User{Username: "alice", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.CreatedAt.IsZero() {
		t.Errorf("Create did not assign ID/CreatedAt: %+v", created)
	}

	if _, err := s.Create(ctx, user.User{Username: "alice"}); !errors.Is(err, user.ErrUsernameTaken) {
		t.Errorf("duplicate Create err = %v, want ErrUsernameTaken", err)
	}

	if got, err := s.ByID(ctx, created.ID); err != nil || got != created {
		t.Errorf("ByID = %+v, %v; want %+v", got, err, created)
	}
	if got, err := s.ByUsername(ctx, "alice"); err != nil || got != created {
		t.Errorf("ByUsername = %+v, %v; want %+v", got, err, created)
	}

	if _, err := s.ByID(ctx, "nope"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("ByID(missing) err = %v, want ErrNotFound", err)
	}
	if _, err := s.ByUsername(ctx, "Alice"); !errors.Is(err, user.ErrNotFound) {
		t.Errorf("ByUsername is not case-sensitive: err = %v", err)
	}
}

func TestSessions(t *testing.T) {
	ctx := t.Context()
	s := NewSessions()
	want := session.Session{ID: "id", UserID: "u"}

	if err := s.Save(ctx, "k", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, err := s.Get(ctx, "k"); err != nil || got != want {
		t.Errorf("Get = %+v, %v; want %+v", got, err, want)
	}

	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Errorf("Delete(missing) = %v, want nil", err)
	}
}
