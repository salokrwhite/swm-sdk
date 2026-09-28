// Package rim2 parses and verifies the SWM release integrity manifest v2.
package rim2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	maximumManifestBytes = 64 * 1024
	maximumFiles         = 255
	maximumPathBytes     = 255
)

var (
	magic          = []byte("OPLUSRIM")
	manifestDomain = []byte("OPLUS_RELEASE_MANIFEST_V2\x00")
	keyDomain      = []byte("OPLUS_RELEASE_KEY_V2\x00")
)

// Error describes a RIM2 validation failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

// File is one signed package entry.
type File struct {
	Path   string
	Size   uint64
	SHA256 [32]byte
}

// Manifest is a verified RIM2 manifest.
type Manifest struct {
	RawBytes       []byte
	ManifestSHA256 string
	AppID          string
	ReleaseID      string
	VersionCode    uint64
	Version        string
	Arch           string
	RootKeyID      string
	SignerKeyID    string
	Files          []File
}

// ParseAndVerify verifies all signatures and release identity fields.
func ParseAndVerify(
	raw []byte,
	expectedAppID, expectedReleaseID, expectedVersion string,
	expectedVersionCode *int,
	expectedArch, expectedRootKeyID, rootTrustPublicKey string,
) (*Manifest, error) {
	if len(raw) == 0 || len(raw) > maximumManifestBytes {
		return nil, fail("host_manifest_invalid", "RIM2 manifest size is invalid")
	}
	if len(raw) < len(magic) || string(raw[:len(magic)]) != string(magic) {
		return nil, fail("host_manifest_invalid", "RIM2 manifest magic is invalid")
	}
	offset := len(magic)
	protocolVersion, err := readU16(raw, &offset)
	if err != nil {
		return nil, err
	}
	bodySize, err := readU32(raw, &offset)
	if err != nil {
		return nil, err
	}
	if protocolVersion != 2 || bodySize == 0 || int(bodySize) > len(raw)-offset {
		return nil, fail("host_manifest_invalid", "RIM2 manifest header is invalid")
	}
	body := raw[offset : offset+int(bodySize)]
	offset += int(bodySize)
	bodyOffset := 0
	if len(body) < 32 {
		return nil, fail("host_manifest_invalid", "RIM2 manifest body is truncated")
	}
	appBytes := append([]byte(nil), body[bodyOffset:bodyOffset+16]...)
	bodyOffset += 16
	releaseBytes := append([]byte(nil), body[bodyOffset:bodyOffset+16]...)
	bodyOffset += 16
	versionCode, err := readU64(body, &bodyOffset)
	if err != nil {
		return nil, err
	}
	if bodyOffset+2 > len(body) {
		return nil, fail("host_manifest_invalid", "RIM2 manifest body is truncated")
	}
	platform := body[bodyOffset]
	architecture := body[bodyOffset+1]
	bodyOffset += 2
	version, err := readString16(body, &bodyOffset)
	if err != nil {
		return nil, err
	}
	if version == "" || len(version) > 100 {
		return nil, fail("host_manifest_invalid", "RIM2 release version is invalid")
	}
	fileCount, err := readU16(body, &bodyOffset)
	if err != nil {
		return nil, err
	}
	if fileCount == 0 || fileCount > maximumFiles {
		return nil, fail("host_manifest_invalid", "RIM2 manifest file count is invalid")
	}
	files := make([]File, 0, fileCount)
	seen := make(map[string]struct{}, fileCount)
	for index := 0; index < int(fileCount); index++ {
		path, err := readString16(body, &bodyOffset)
		if err != nil {
			return nil, err
		}
		size, err := readU64(body, &bodyOffset)
		if err != nil {
			return nil, err
		}
		if bodyOffset+32 > len(body) {
			return nil, fail("host_manifest_invalid", "RIM2 manifest file hash is truncated")
		}
		var hash [32]byte
		copy(hash[:], body[bodyOffset:bodyOffset+32])
		bodyOffset += 32
		if !safePath(path) || size == 0 || allZero(hash[:]) {
			return nil, fail("host_manifest_invalid", "RIM2 manifest contains an unsafe or empty file")
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			return nil, fail("host_manifest_invalid", "RIM2 manifest contains a duplicate file path")
		}
		seen[key] = struct{}{}
		files = append(files, File{Path: path, Size: size, SHA256: hash})
	}
	if bodyOffset != len(body) {
		return nil, fail("host_manifest_invalid", "RIM2 manifest body contains trailing bytes")
	}
	trailer := offset
	rootKeyID, err := readString8(raw, &trailer)
	if err != nil {
		return nil, err
	}
	signerKeyID, err := readString8(raw, &trailer)
	if err != nil {
		return nil, err
	}
	if rootKeyID == "" || len(rootKeyID) > 64 || signerKeyID == "" || len(signerKeyID) > 64 {
		return nil, fail("host_manifest_invalid", "RIM2 signing key id is invalid")
	}
	if trailer+160 > len(raw) {
		return nil, fail("host_manifest_invalid", "RIM2 manifest trailer is truncated")
	}
	signerPublicKey := append([]byte(nil), raw[trailer:trailer+32]...)
	trailer += 32
	rootCertificateSignature := append([]byte(nil), raw[trailer:trailer+64]...)
	trailer += 64
	manifestSignature := append([]byte(nil), raw[trailer:trailer+64]...)
	trailer += 64
	if trailer != len(raw) {
		return nil, fail("host_manifest_invalid", "RIM2 manifest trailer is invalid")
	}
	expectedAppBytes, err := uuidBytes(expectedAppID)
	if err != nil {
		return nil, fail("host_manifest_invalid", "expected app id is invalid")
	}
	expectedReleaseBytes, err := uuidBytes(expectedReleaseID)
	if err != nil {
		return nil, fail("host_manifest_invalid", "expected release id is invalid")
	}
	versionCodeMatches := true
	if expectedVersionCode != nil {
		versionCodeMatches = versionCode == uint64(*expectedVersionCode)
	}
	if string(appBytes) != string(expectedAppBytes) ||
		string(releaseBytes) != string(expectedReleaseBytes) ||
		platform != 1 ||
		architecture != archByte(expectedArch) ||
		version != expectedVersion ||
		!versionCodeMatches ||
		rootKeyID != expectedRootKeyID {
		return nil, fail("host_release_mismatch", "RIM2 manifest identity does not match this release")
	}
	keyMessage := make([]byte, 0, len(keyDomain)+16+1+len(rootKeyID)+1+len(signerKeyID)+32)
	keyMessage = append(keyMessage, keyDomain...)
	keyMessage = append(keyMessage, appBytes...)
	keyMessage = appendString8(keyMessage, rootKeyID)
	keyMessage = appendString8(keyMessage, signerKeyID)
	keyMessage = append(keyMessage, signerPublicKey...)
	rootKey, err := decodeKey(rootTrustPublicKey)
	if err != nil || len(rootKey) != ed25519.PublicKeySize {
		return nil, fail("host_root_signature_invalid", "RIM2 root trust key is invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(rootKey), keyMessage, rootCertificateSignature) {
		return nil, fail("host_root_signature_invalid", "RIM2 root certificate signature is invalid")
	}
	if len(signerPublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(signerPublicKey), append(append([]byte(nil), manifestDomain...), body...), manifestSignature) {
		return nil, fail("host_manifest_signature_invalid", "RIM2 manifest signature is invalid")
	}
	return &Manifest{
		RawBytes:       append([]byte(nil), raw...),
		ManifestSHA256: sha256Hex(raw),
		AppID:          expectedAppID,
		ReleaseID:      expectedReleaseID,
		VersionCode:    versionCode,
		Version:        version,
		Arch:           normalizeArch(architecture),
		RootKeyID:      rootKeyID,
		SignerKeyID:    signerKeyID,
		Files:          files,
	}, nil
}

func fail(code, message string) error {
	return &Error{Code: code, Message: message}
}

func readU16(value []byte, offset *int) (uint16, error) {
	if *offset < 0 || *offset+2 > len(value) {
		return 0, fail("host_manifest_invalid", "RIM2 manifest is truncated")
	}
	result := binary.BigEndian.Uint16(value[*offset:])
	*offset += 2
	return result, nil
}

func readU32(value []byte, offset *int) (uint32, error) {
	if *offset < 0 || *offset+4 > len(value) {
		return 0, fail("host_manifest_invalid", "RIM2 manifest is truncated")
	}
	result := binary.BigEndian.Uint32(value[*offset:])
	*offset += 4
	return result, nil
}

func readU64(value []byte, offset *int) (uint64, error) {
	if *offset < 0 || *offset+8 > len(value) {
		return 0, fail("host_manifest_invalid", "RIM2 manifest is truncated")
	}
	result := binary.BigEndian.Uint64(value[*offset:])
	*offset += 8
	return result, nil
}

func readString8(value []byte, offset *int) (string, error) {
	if *offset < 0 || *offset+1 > len(value) {
		return "", fail("host_manifest_invalid", "RIM2 manifest is truncated")
	}
	length := int(value[*offset])
	*offset++
	return readUTF8(value, offset, length)
}

func readString16(value []byte, offset *int) (string, error) {
	length, err := readU16(value, offset)
	if err != nil {
		return "", err
	}
	return readUTF8(value, offset, int(length))
}

func readUTF8(value []byte, offset *int, length int) (string, error) {
	if *offset < 0 || length < 0 || *offset+length > len(value) {
		return "", fail("host_manifest_invalid", "RIM2 manifest is truncated")
	}
	result := value[*offset : *offset+length]
	*offset += length
	if !utf8.Valid(result) {
		return "", fail("host_manifest_invalid", "RIM2 manifest contains invalid UTF-8")
	}
	return string(result), nil
}

func appendString8(target []byte, value string) []byte {
	return append(append(target, byte(len(value))), value...)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func safePath(value string) bool {
	if value == "" || len(value) > maximumPathBytes ||
		strings.Contains(value, `\`) ||
		strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") ||
		strings.Contains(value, ":") ||
		strings.ContainsRune(value, 0) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func archByte(value string) byte {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86", "386", "i386", "win-x86":
		return 1
	case "x64", "amd64", "win-x64":
		return 2
	default:
		return 0
	}
}

func normalizeArch(value byte) string {
	switch value {
	case 1:
		return "x86"
	case 2:
		return "x64"
	default:
		return ""
	}
}

func uuidBytes(value string) ([]byte, error) {
	clean := strings.ReplaceAll(value, "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("invalid UUID")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	return []byte{
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	}, nil
}

func decodeKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty key")
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(value)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
