package authn

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "Password123!"
	hash := HashPassword(password)

	if !phcRegex.MatchString(hash) {
		t.Errorf("expected hash to match PHC format, got: %s", hash)
	}
}

func TestVerifyPassword(t *testing.T) {
	storedHash := HashPassword("Password123!")

	tests := []struct {
		name       string
		password   string
		storedHash string
		wantErr    any
	}{
		{
			name:       "valid password",
			password:   "Password123!",
			storedHash: storedHash,
			wantErr:    nil,
		},
		{
			name:       "invalid password",
			password:   "Password321?",
			storedHash: storedHash,
			wantErr:    ErrInvalidPassword,
		},
		{
			name:       "invalid identifier",
			password:   "Password123!",
			storedHash: "$argon2$v=19$m=65536,t=3,p=4$invalidsalt$invalidhash",
			wantErr:    "invalid identifier",
		},
		{
			name:       "invalid hash format",
			password:   "Password123!",
			storedHash: "$argon2id$v=19$m=65536,t=3,p=4$hash123",
			wantErr:    "invalid hash format",
		},
		{
			name:       "invalid argon2 version",
			password:   "Password123!",
			storedHash: "$argon2id$v=nineteen$m=65536,t=3,p=4$salt123$hash123",
			wantErr:    "failed to parse argon2 version",
		},
		{
			name:       "unsupported argon2 version",
			password:   "Password123!",
			storedHash: "$argon2id$v=18$m=65536,t=3,p=4$salt123$hash123",
			wantErr:    "unsupported argon2 version",
		},
		{
			name:       "invalid parameters",
			password:   "Password123!",
			storedHash: "$argon2id$v=19$m=65536,t=3$salt123$hash123",
			wantErr:    "failed to parse parameters",
		},
		{
			name:       "invalid salt encoding",
			password:   "Password123!",
			storedHash: "$argon2id$v=19$m=65536,t=3,p=4$invalid???salt$hash123",
			wantErr:    "failed to decode salt",
		},
		{
			name:       "invalid key encoding",
			password:   "Password123!",
			storedHash: "$argon2id$v=19$m=65536,t=3,p=4$salt123$invalid???hash",
			wantErr:    "failed to decode key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyPassword(tc.password, tc.storedHash)

			switch target := tc.wantErr.(type) {
			case nil:
				if err != nil {
					t.Errorf("VerifyPassword() unexpected error: %v", err)
				}
			case error:
				if !errors.Is(err, target) {
					t.Errorf("VerifyPassword() = %v; want %v", err, tc.wantErr)
				}
			case string:
				if err == nil {
					t.Errorf("VerifyPassword() expected error containing %q, got nil", target)
				}

				if !strings.Contains(err.Error(), target) {
					t.Errorf("VerifyPassword() error = %v; want error containing %q", err, target)
				}
			default:
				t.Fatalf("unknown err type configured in test case: %T", tc.wantErr)
			}
		})
	}

}
