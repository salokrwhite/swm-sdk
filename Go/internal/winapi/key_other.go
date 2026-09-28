//go:build !windows

package winapi

// IdentityKey is unavailable outside Windows.
type IdentityKey struct{}

// CreateIdentityKey is unavailable outside Windows.
func CreateIdentityKey(string) (*IdentityKey, error) {
	return nil, ErrUnsupportedPlatform
}

// OpenIdentityKey is unavailable outside Windows.
func OpenIdentityKey(string) (*IdentityKey, error) {
	return nil, ErrUnsupportedPlatform
}

// Name returns the persisted key name.
func (*IdentityKey) Name() string { return "" }

// PublicKeySEC1 is unavailable outside Windows.
func (*IdentityKey) PublicKeySEC1() ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// SignDigest is unavailable outside Windows.
func (*IdentityKey) SignDigest([]byte) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// Delete is unavailable outside Windows.
func (*IdentityKey) Delete() error { return ErrUnsupportedPlatform }

// Close is unavailable outside Windows.
func (*IdentityKey) Close() error { return nil }
