//go:build windows && (amd64 || 386)

package winapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestIdentityKeyCreateSignAndDelete(t *testing.T) {
	nameBytes := make([]byte, 8)
	if _, err := rand.Read(nameBytes); err != nil {
		t.Fatal(err)
	}
	key, err := CreateIdentityKey("SwmSdk.GoTest." + hex.EncodeToString(nameBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Delete()

	publicKey, err := key.PublicKeySEC1()
	if err != nil {
		t.Fatal(err)
	}
	if len(publicKey) != 65 || publicKey[0] != 4 {
		t.Fatalf("unexpected SEC1 public key: %x", publicKey)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil || y == nil {
		t.Fatal("failed to parse SEC1 public key")
	}
	digest := sha256.Sum256([]byte("swm go sdk test"))
	signature, err := key.SignDigest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("unexpected P1363 signature length: %d", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s) {
		t.Fatal("P1363 signature did not verify")
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDPAPIRoundTrip(t *testing.T) {
	entropy := []byte("SwmSdkStateV2\n00000000-0000-0000-0000-000000000001")
	plaintext := []byte("v2\n0123456789abcdef0123456789abcdef\nSwmSdk.key\n")
	ciphertext, err := Protect(plaintext, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("DPAPI ciphertext matched plaintext")
	}
	decoded, err := Unprotect(ciphertext, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("DPAPI round trip mismatch: %q", decoded)
	}
}

func TestCollectHardwareEvidence(t *testing.T) {
	evidence, err := CollectHardwareEvidence("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Version != 2 || evidence.ComponentMask == 0 || len(evidence.AggregateHash) != 64 {
		t.Fatalf("unexpected hardware evidence: %#v", evidence)
	}
}
