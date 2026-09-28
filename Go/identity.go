package swm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/salokrwhite/swm-sdk/Go/v2/internal/winapi"
)

type deviceIdentity struct {
	store         *stateStore
	key           *winapi.IdentityKey
	installID     string
	deviceID      string
	keyID         string
	keyThumbprint string
	publicKeySEC1 []byte
	mu            sync.Mutex
}

func loadOrCreateIdentity(appID string, store *stateStore) (*deviceIdentity, error) {
	if installID, keyName, ok := readIdentityMetadata(store); ok {
		key, err := winapi.OpenIdentityKey(keyName)
		if err == nil {
			identity, err := identityFromKey(store, installID, key)
			if err == nil {
				return identity, nil
			}
			_ = key.Close()
		}
		store.delete(identityFile)
	}
	installIDBytes, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	installID := strings.ToLower(fmt.Sprintf("%x", installIDBytes))
	keyName := buildKeyName(appID, installID)
	key, err := winapi.CreateIdentityKey(keyName)
	if err != nil {
		return nil, wrapError(KindIdentity, "create device key", err)
	}
	identity, err := identityFromKey(store, installID, key)
	if err != nil {
		_ = key.Delete()
		return nil, err
	}
	if err := writeIdentityMetadata(store, installID, keyName); err != nil {
		_ = key.Delete()
		return nil, err
	}
	return identity, nil
}

func createPendingIdentity(appID string, store *stateStore) (*deviceIdentity, error) {
	installIDBytes, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	installID := strings.ToLower(fmt.Sprintf("%x", installIDBytes))
	keyName := buildKeyName(appID, installID)
	key, err := winapi.CreateIdentityKey(keyName)
	if err != nil {
		return nil, wrapError(KindIdentity, "create pending device key", err)
	}
	identity, err := identityFromKey(store, installID, key)
	if err != nil {
		_ = key.Delete()
		return nil, err
	}
	return identity, nil
}

func identityFromKey(store *stateStore, installID string, key *winapi.IdentityKey) (*deviceIdentity, error) {
	publicKey, err := key.PublicKeySEC1()
	if err != nil {
		return nil, wrapError(KindIdentity, "export device public key", err)
	}
	thumbprint := base64URLEncode(sha256Bytes(publicKey))
	deviceID := sha256Hex([]byte(
		"device_credential_v2\napp_id:" + store.appID +
			"\ninstall_id:" + installID +
			"\nkey_thumbprint:" + thumbprint,
	))
	keyID := "swm-device-" + thumbprint[:22]
	return &deviceIdentity{
		store:         store,
		key:           key,
		installID:     installID,
		deviceID:      deviceID,
		keyID:         keyID,
		keyThumbprint: thumbprint,
		publicKeySEC1: publicKey,
	}, nil
}

func buildKeyName(appID, installID string) string {
	appHash := sha256Hex([]byte(appID))[:12]
	return "SwmSdk." + appHash + "." + installID
}

func readIdentityMetadata(store *stateStore) (string, string, bool) {
	plaintext, ok := store.readProtected(identityFile)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(string(plaintext), "\n")
	if len(parts) < 3 || parts[0] != "v2" || len(parts[1]) != 32 || strings.TrimSpace(parts[2]) == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func writeIdentityMetadata(store *stateStore, installID, keyName string) error {
	return store.writeProtected(identityFile, []byte("v2\n"+installID+"\n"+keyName+"\n"))
}

func (i *deviceIdentity) signDigest(digest []byte) ([]byte, error) {
	if i == nil || i.key == nil {
		return nil, newError(KindIdentity, "sign", "identity_missing", "device identity is unavailable")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	signature, err := i.key.SignDigest(digest)
	if err != nil {
		return nil, wrapError(KindIdentity, "sign", err)
	}
	return signature, nil
}

func (i *deviceIdentity) commitPending() error {
	if i == nil || i.key == nil {
		return newError(KindIdentity, "commit key", "identity_missing", "pending identity is unavailable")
	}
	return writeIdentityMetadata(i.store, i.installID, i.key.Name())
}

func (i *deviceIdentity) deletePending() {
	if i == nil || i.key == nil {
		return
	}
	_ = i.key.Delete()
}

func (i *deviceIdentity) close() {
	if i == nil || i.key == nil {
		return
	}
	_ = i.key.Close()
}
