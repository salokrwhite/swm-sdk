//go:build windows && (amd64 || 386)

package swm

import (
	"testing"
)

func TestStateStoreDPAPIRoundTripAndReplace(t *testing.T) {
	appID := "00000000-0000-0000-0000-000000000101"
	store, err := newStateStore(appID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeProtected("test.bin", []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.writeProtected("test.bin", []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	plaintext, ok := store.readProtected("test.bin")
	if !ok || string(plaintext) != "second\n" {
		t.Fatalf("unexpected state value: %q", plaintext)
	}
}

func TestIdentityCreateReloadAndSign(t *testing.T) {
	appID := "00000000-0000-0000-0000-000000000102"
	store, err := newStateStore(appID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := loadOrCreateIdentity(appID, store)
	if err != nil {
		t.Fatal(err)
	}
	defer first.key.Delete()
	second, err := loadOrCreateIdentity(appID, store)
	if err != nil {
		t.Fatal(err)
	}
	defer second.key.Close()
	if first.deviceID != second.deviceID ||
		first.installID != second.installID ||
		first.keyID != second.keyID ||
		first.keyThumbprint != second.keyThumbprint {
		t.Fatalf("reloaded identity mismatch: %#v %#v", first, second)
	}
	digest := sha256Bytes([]byte("identity test"))
	signature, err := second.signDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("unexpected signature length: %d", len(signature))
	}
}
