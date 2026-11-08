package authn

// ---------------------------------------------------------------------------
// YOUR CODE: password hashing with argon2id.
//
// Use golang.org/x/crypto/argon2 (`go get golang.org/x/crypto/argon2`) for the
// primitive. The decisions are yours: parameters (memory, iterations,
// parallelism, salt and key length), salt generation, the encoding format,
// and how hashes are compared.
//
// Suggested reading:
//   - RFC 9106 (Argon2), section 4 "Parameter Choice"
//   - OWASP Password Storage Cheat Sheet
//   - PHC string format: https://github.com/P-H-C/phc-string-format
// ---------------------------------------------------------------------------

// HashPassword returns a self-describing encoded hash of password, suitable
// for storing in user.User.PasswordHash. The encoding must carry everything
// VerifyPassword needs (algorithm, version, parameters, salt), e.g. the PHC
// string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
func HashPassword(password string) (string, error) { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement HashPassword")
}

// VerifyPassword reports whether password matches encoded, a value produced
// by HashPassword. It returns an error only if encoded is malformed, not for
// a wrong password.
func VerifyPassword(password, encoded string) (bool, error) { //nolint:revive // TODO: remove once implemented (unused params)
	panic("TODO: implement VerifyPassword")
}
