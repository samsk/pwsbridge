package policy

import (
	"crypto/sha256"
	"crypto/subtle"
)

// AuthMode is open or password.
type AuthMode string

const (
	AuthOpen     AuthMode = "open"
	AuthPassword AuthMode = "password"
)

// CheckPassword compares secrets in constant time via SHA-256 digests.
// Empty want always fails. Length differences do not short-circuit the compare.
func CheckPassword(want, got string) bool {
	if len(want) == 0 {
		return false
	}
	a := sha256.Sum256([]byte(want))
	b := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
