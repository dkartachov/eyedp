package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

var phcRegex = regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

// HashPassword returns a self-describing encoded hash of password, suitable
// for storing in user.User.PasswordHash. The encoding must carry everything
// VerifyPassword needs (algorithm, version, parameters, salt), e.g. the PHC
// string format:
//
// $argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
func HashPassword(password string) string {
	salt := generateSalt(16)

	// second recommended parameters from RFC 9106, section 4.1.2
	memory := uint32(64 * 1024) // 64 MiB
	time := uint32(3)           // 3 iterations
	parallelism := uint8(4)     // 4 threads
	keyLength := uint32(32)     // 32 bytes

	key := argon2.IDKey([]byte(password), salt, time, memory, parallelism, keyLength)

	saltEncoded := base64.RawStdEncoding.EncodeToString(salt)
	keyEncoded := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, parallelism, saltEncoded, keyEncoded)
}

var ErrInvalidPassword = errors.New("authn: invalid password")

// VerifyPassword reports whether password matches encoded, a value produced
// by HashPassword. It returns an error only if encoded is malformed, not for
// a wrong password.
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")

	if len(parts) != 6 {
		return fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return fmt.Errorf("invalid identifier")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return fmt.Errorf("failed to parse argon2 version: %w", err)
	}

	if version != argon2.Version {
		return fmt.Errorf("unsupported argon2 version: %d", version)
	}

	var memory, time uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism)
	if err != nil {
		return fmt.Errorf("failed to parse parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	originalKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	keyLength := uint32(len(originalKey))
	computedKey := argon2.IDKey([]byte(password), salt, time, memory, parallelism, keyLength)

	if subtle.ConstantTimeCompare(originalKey, computedKey) == 1 {
		return nil
	}

	return ErrInvalidPassword
}

func generateSalt(length int) []byte {
	salt := make([]byte, length)

	rand.Read(salt)

	return salt
}
