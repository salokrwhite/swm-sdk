//go:build !windows

package winapi

// Protect is unavailable outside Windows.
func Protect(plaintext, entropy []byte) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// Unprotect is unavailable outside Windows.
func Unprotect(ciphertext, entropy []byte) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// ReplaceFile is unavailable outside Windows.
func ReplaceFile(source, destination string) error {
	return ErrUnsupportedPlatform
}
