package swm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEd25519ToX25519AndEncryptedBodyRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	converted, err := ed25519PublicKeyToX25519(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	xPrivate := x25519PrivateFromSeed(seed)
	if !bytes.Equal(converted, xPrivate.PublicKey().Bytes()) {
		t.Fatal("Ed25519 public key conversion did not match X25519 public key")
	}
	plaintext := []byte(`{"hello":"world"}`)
	sealed, err := encryptRequestBody(
		"POST",
		"/api/client/update-check",
		"",
		1234567890,
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"app",
		"1.2.3",
		nil,
		"key-1",
		hex.EncodeToString(publicKey),
		plaintext,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) < 32+12+16 {
		t.Fatalf("encrypted body is too short: %d", len(sealed))
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := xPrivate.ECDH(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := strings.Join([]string{
		bodyEncryptionLabel,
		"app_id:00000000-0000-0000-0000-000000000002",
		"release_id:app",
		"key_id:key-1",
		"public_key:" + hex.EncodeToString(publicKey),
	}, "\n")
	salt := sha256Bytes([]byte(contextValue))
	info := contextValue + "\nephemeral_public:" + base64URLEncode(sealed[:32])
	key, err := hkdfKey(shared, salt, info)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := buildBodyEncryptionAAD(
		"POST",
		"/api/client/update-check",
		"",
		1234567890,
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"app",
		"1.2.3",
		nil,
		"key-1",
	)
	decoded, err := aead.Open(nil, sealed[32:44], sealed[44:], []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("decrypted body mismatch: %q", decoded)
	}
}

func x25519PrivateFromSeed(seed []byte) *ecdh.PrivateKey {
	digest := sha512.Sum512(seed)
	value := digest[:32]
	value[0] &= 248
	value[31] &= 127
	value[31] |= 64
	key, err := ecdh.X25519().NewPrivateKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func hkdfKey(shared, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, salt, info, 32)
}
