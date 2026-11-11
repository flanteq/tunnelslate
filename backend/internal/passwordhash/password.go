// Package passwordhash stores new passwords with PBKDF2-HMAC-SHA256 and keeps
// existing bcrypt credentials readable until the administrator changes them.
package passwordhash

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// PBKDF2-HMAC-SHA256 work factor:
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
const iterations = 600_000

var errInvalid = errors.New("invalid password or password hash")

func ValidNew(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 12 && length <= 72
}

func Hash(value string) (string, error) {
	if !ValidNew(value) {
		return "", errInvalid
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, value, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	return "$pbkdf2-sha256$i=" + strconv.Itoa(iterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func Verify(encoded, value string) error {
	// Do not apply the new minimum to existing bcrypt passwords: earlier
	// versions accepted passwords with fewer Unicode characters.
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 72 {
		return errInvalid
	}
	if strings.HasPrefix(encoded, "$2") {
		// bcrypt comparisons otherwise silently ignore input beyond 72 bytes.
		if len(value) > 72 {
			return errInvalid
		}
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(value))
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" || !strings.HasPrefix(parts[2], "i=") {
		return errInvalid
	}
	work, err := strconv.Atoi(strings.TrimPrefix(parts[2], "i="))
	if err != nil || work < iterations || work > 2_000_000 {
		return errInvalid
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(salt) != 16 {
		return errInvalid
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(expected) != 32 {
		return errInvalid
	}
	actual, err := pbkdf2.Key(sha256.New, value, salt, work, len(expected))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return errInvalid
	}
	return nil
}
