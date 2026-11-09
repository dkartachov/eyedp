package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

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

var (
	// ErrInvalidPassword is returned by VerifyPassword when the password does not match the stored hash.
	ErrInvalidPassword = errors.New("authn: invalid password")
	// ErrMalformedHash is returned by VerifyPassword when the stored hash is malformed or cannot be parsed.
	ErrMalformedHash = errors.New("authn: malformed encoded hash")
)

// TODO(review): improvements for VerifyPassword
//   - Bound the parsed parameters before calling argon2.IDKey. Today these
//     crash the process instead of returning an error:
//     t=0 -> panic "number of rounds too small"
//     p=0 -> panic "parallelism degree too low"
//     empty key section -> keyLen 0 -> nil blake2b hash -> panic
//     huge m (e.g. 4294967295) -> ~4 TiB allocation -> OOM
//     Reject t < 1, p < 1, key length 0, and values above sane limits
//     (e.g. m > 1 GiB, salt/key too short or too long).
//   - fmt.Sscanf ignores trailing input ("v=19garbage", "m=..,p=4,x=1" parse).
//     Make parsing strict, e.g. re-format the parsed values and compare.
//   - uint32(len(originalKey)) trips gosec G115; a key length bound fixes it.

// VerifyPassword reports whether password matches encoded, a value produced
// by HashPassword. It returns ErrInvalidPassword if the password does not match,
// and other errors for a malformed encoded hash.
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")

	if len(parts) != 6 {
		return fmt.Errorf("%w: invalid hash format", ErrMalformedHash)
	}

	if parts[1] != "argon2id" {
		return fmt.Errorf("%w: invalid identifier", ErrMalformedHash)
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return fmt.Errorf("%w: failed to parse argon2 version: %w", ErrMalformedHash, err)
	}

	if version != argon2.Version {
		return fmt.Errorf("%w: unsupported argon2 version: %d", ErrMalformedHash, version)
	}

	var memory, time uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism)
	if err != nil {
		return fmt.Errorf("%w: failed to parse parameters: %w", ErrMalformedHash, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("%w: failed to decode salt: %w", ErrMalformedHash, err)
	}

	originalKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("%w: failed to decode key: %w", ErrMalformedHash, err)
	}

	// #nosec G115 - Key length will never exceed math.MaxUint32
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
