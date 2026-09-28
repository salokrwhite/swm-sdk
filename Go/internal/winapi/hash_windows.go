//go:build windows

package winapi

import (
	"crypto/sha256"
	"encoding/hex"
)

func hashHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
