package rim2

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestParseAndVerify(t *testing.T) {
	const (
		appID       = "00000000-0000-0000-0000-000000000001"
		releaseID   = "00000000-0000-0000-0000-000000000002"
		version     = "1.2.3"
		versionCode = 10203
		arch        = "x64"
		rootKeyID   = "root-1"
		signerKeyID = "signer-1"
		path        = "app.exe"
	)
	fileHash := make([]byte, 32)
	for i := range fileHash {
		fileHash[i] = byte(i)
	}
	raw, rootPublic := buildTestManifest(
		t, appID, releaseID, version, versionCode, arch,
		rootKeyID, signerKeyID, path, fileHash,
	)
	versionCodeValue := versionCode
	manifest, err := ParseAndVerify(
		raw,
		appID,
		releaseID,
		version,
		&versionCodeValue,
		arch,
		rootKeyID,
		rootPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != version || manifest.Arch != arch ||
		len(manifest.Files) != 1 || manifest.Files[0].Path != path {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestParseAndVerifyRejectsTampering(t *testing.T) {
	const (
		appID       = "00000000-0000-0000-0000-000000000003"
		releaseID   = "00000000-0000-0000-0000-000000000004"
		version     = "1.2.3"
		versionCode = 10203
		arch        = "x64"
	)
	fileHash := make([]byte, 32)
	raw, rootPublic := buildTestManifest(
		t, appID, releaseID, version, versionCode, arch,
		"root-1", "signer-1", "app.exe", fileHash,
	)
	raw[len(raw)-1] ^= 0x01
	versionCodeValue := versionCode
	if _, err := ParseAndVerify(
		raw,
		appID,
		releaseID,
		version,
		&versionCodeValue,
		arch,
		"root-1",
		rootPublic,
	); err == nil {
		t.Fatal("tampered RIM2 manifest was accepted")
	}
}

func buildTestManifest(
	t *testing.T,
	appID, releaseID, version string,
	versionCode int,
	arch, rootKeyID, signerKeyID, filePath string,
	fileHash []byte,
) ([]byte, string) {
	t.Helper()
	rootSeed := make([]byte, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	signerSeed := make([]byte, ed25519.SeedSize)
	for i := range signerSeed {
		signerSeed[i] = byte(i + 1)
	}
	signerPrivate := ed25519.NewKeyFromSeed(signerSeed)
	signerPublic := signerPrivate.Public().(ed25519.PublicKey)

	appBytes, err := uuidBytes(appID)
	if err != nil {
		t.Fatal(err)
	}
	releaseBytes, err := uuidBytes(releaseID)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 0, 256)
	body = append(body, appBytes...)
	body = append(body, releaseBytes...)
	body = appendU64(body, uint64(versionCode))
	body = append(body, 1)
	if arch == "x86" {
		body = append(body, 1)
	} else {
		body = append(body, 2)
	}
	body = appendString16(body, version)
	body = appendU16(body, 1)
	body = appendString16(body, filePath)
	body = appendU64(body, 1234)
	body = append(body, fileHash...)

	keyMessage := append([]byte(nil), keyDomain...)
	keyMessage = append(keyMessage, appBytes...)
	keyMessage = testAppendString8(keyMessage, rootKeyID)
	keyMessage = testAppendString8(keyMessage, signerKeyID)
	keyMessage = append(keyMessage, signerPublic...)
	rootSignature := ed25519.Sign(rootPrivate, keyMessage)
	manifestSignature := ed25519.Sign(signerPrivate, append(append([]byte(nil), manifestDomain...), body...))

	raw := append([]byte(nil), magic...)
	raw = appendU16(raw, 2)
	raw = appendU32(raw, uint32(len(body)))
	raw = append(raw, body...)
	raw = testAppendString8(raw, rootKeyID)
	raw = testAppendString8(raw, signerKeyID)
	raw = append(raw, signerPublic...)
	raw = append(raw, rootSignature...)
	raw = append(raw, manifestSignature...)
	return raw, hex.EncodeToString(rootPublic)
}

func appendU16(target []byte, value uint16) []byte {
	var buffer [2]byte
	binary.BigEndian.PutUint16(buffer[:], value)
	return append(target, buffer[:]...)
}

func appendU32(target []byte, value uint32) []byte {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	return append(target, buffer[:]...)
}

func appendU64(target []byte, value uint64) []byte {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	return append(target, buffer[:]...)
}

func testAppendString8(target []byte, value string) []byte {
	return append(append(target, byte(len(value))), value...)
}

func appendString16(target []byte, value string) []byte {
	return append(appendU16(target, uint16(len(value))), value...)
}
