package swm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const bodyEncryptionLabel = "swm-body-x25519-aes-gcm-v1"

func sha256Bytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, wrapError(KindCryptographic, "random", err)
	}
	return value, nil
}

func randomUUID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}

func base64URLEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func base64URLDecode(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func decodeKeyMaterial(value string) ([]byte, error) {
	input := strings.TrimSpace(value)
	if input == "" {
		return nil, fmt.Errorf("empty key material")
	}
	if len(input)%2 == 0 {
		if decoded, err := hex.DecodeString(input); err == nil {
			return decoded, nil
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
		return decoded, nil
	}
	return base64URLDecode(input)
}

func verifyEd25519(publicKey string, message []byte, signature string) (bool, error) {
	key, err := decodeKeyMaterial(publicKey)
	if err != nil {
		return false, wrapError(KindCryptographic, "verify ed25519", err)
	}
	sig, err := decodeKeyMaterial(signature)
	if err != nil {
		return false, wrapError(KindCryptographic, "verify ed25519", err)
	}
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false, newError(KindCryptographic, "verify ed25519", "invalid_key_material", "invalid Ed25519 key or signature")
	}
	return ed25519.Verify(ed25519.PublicKey(key), message, sig), nil
}

func hmacSHA256Hex(secret string, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalQuery(raw url.Values) string {
	if len(raw) == 0 {
		return ""
	}
	type pair struct {
		key   string
		value string
	}
	pairs := make([]pair, 0, len(raw))
	for key, values := range raw {
		for _, value := range values {
			pairs = append(pairs, pair{key: key, value: value})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	parts := make([]string, 0, len(pairs))
	for _, item := range pairs {
		parts = append(parts, escapeCanonical(item.key)+"="+escapeCanonical(item.value))
	}
	return strings.Join(parts, "&")
}

func escapeCanonical(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func encryptRequestBody(
	method, path, query string,
	timestamp int64,
	nonce string,
	appID, releaseID, releaseVersion string,
	releaseVersionCode *int,
	onlineKeyID, onlinePublicKey string,
	plaintext []byte,
) ([]byte, error) {
	edKey, err := decodeKeyMaterial(onlinePublicKey)
	if err != nil || len(edKey) != 32 {
		return nil, newError(KindCryptographic, "encrypt body", "online_key_invalid", "online authorization key must be a 32-byte Ed25519 key")
	}
	xKeyBytes, err := ed25519PublicKeyToX25519(edKey)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	curve := ecdh.X25519()
	serverKey, err := curve.NewPublicKey(xKeyBytes)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	shared, err := ephemeral.ECDH(serverKey)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	ephemeralPublic := ephemeral.PublicKey().Bytes()
	contextValue := strings.Join([]string{
		bodyEncryptionLabel,
		"app_id:" + appID,
		"release_id:" + releaseID,
		"key_id:" + onlineKeyID,
		"public_key:" + hex.EncodeToString(edKey),
	}, "\n")
	salt := sha256Bytes([]byte(contextValue))
	info := contextValue + "\nephemeral_public:" + base64URLEncode(ephemeralPublic)
	requestKey, err := hkdf.Key(sha256.New, shared, salt, info, 32)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	defer zero(requestKey)
	block, err := aes.NewCipher(requestKey)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapError(KindCryptographic, "encrypt body", err)
	}
	aesNonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	aad := buildBodyEncryptionAAD(
		method, path, query, timestamp, nonce,
		appID, releaseID, releaseVersion, releaseVersionCode, onlineKeyID)
	ciphertext := aead.Seal(nil, aesNonce, plaintext, []byte(aad))
	sealed := make([]byte, 0, len(ephemeralPublic)+len(aesNonce)+len(ciphertext))
	sealed = append(sealed, ephemeralPublic...)
	sealed = append(sealed, aesNonce...)
	sealed = append(sealed, ciphertext...)
	return sealed, nil
}

func buildBodyEncryptionAAD(
	method, path, query string,
	timestamp int64,
	nonce string,
	appID, releaseID, releaseVersion string,
	releaseVersionCode *int,
	onlineKeyID string,
) string {
	versionCode := ""
	if releaseVersionCode != nil {
		versionCode = strconv.Itoa(*releaseVersionCode)
	}
	return strings.Join([]string{
		bodyEncryptionLabel,
		strings.ToUpper(method),
		path,
		query,
		"",
		strconv.FormatInt(timestamp, 10),
		nonce,
		appID,
		"client_release_id:" + releaseID,
		"client_version:" + releaseVersion,
		"client_version_code:" + versionCode,
		"authz_capability:v3",
		"body_enc:x25519-aes-gcm-v1",
		"key_id:" + onlineKeyID,
	}, "\n")
}

func ed25519PublicKeyToX25519(encoded []byte) ([]byte, error) {
	if len(encoded) != 32 {
		return nil, fmt.Errorf("authorization public key has invalid length")
	}
	littleY := append([]byte(nil), encoded...)
	littleY[31] &= 0x7f
	for i, j := 0, len(littleY)-1; i < j; i, j = i+1, j-1 {
		littleY[i], littleY[j] = littleY[j], littleY[i]
	}
	y := new(big.Int).SetBytes(littleY)
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	if y.Sign() < 0 || y.Cmp(prime) >= 0 {
		return nil, fmt.Errorf("authorization Ed25519 public key is not canonical")
	}
	denominator := new(big.Int).Sub(big.NewInt(1), y)
	denominator.Mod(denominator, prime)
	if denominator.Sign() == 0 {
		return nil, fmt.Errorf("authorization Ed25519 public key cannot be converted")
	}
	inverse := new(big.Int).ModInverse(denominator, prime)
	numerator := new(big.Int).Add(big.NewInt(1), y)
	u := new(big.Int).Mul(numerator, inverse)
	u.Mod(u, prime)
	be := u.FillBytes(make([]byte, 32))
	result := make([]byte, 32)
	for i := range result {
		result[i] = be[len(be)-1-i]
	}
	return result, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
