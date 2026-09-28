package swm

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/salokrwhite/swm-sdk/Go/v2/internal/winapi"
)

const (
	identityFile        = "identity.bin"
	offlineFile         = "offline.bin"
	integrityPolicyFile = "integrity-policy.bin"
)

type stateStore struct {
	directory string
	appID     string
	entropy   []byte
}

func newStateStore(appID, override string) (*stateStore, error) {
	directory := override
	if directory == "" {
		var err error
		directory, err = defaultStorageDirectory(appID)
		if err != nil {
			return nil, err
		}
	} else {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return nil, wrapError(KindIdentity, "storage", err)
		}
		directory = absolute
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, wrapError(KindIdentity, "storage", err)
	}
	return &stateStore{
		directory: directory,
		appID:     appID,
		entropy:   sha256Bytes([]byte("SwmSdkStateV2\n" + appID)),
	}, nil
}

func (s *stateStore) path(fileName string) string {
	return filepath.Join(s.directory, fileName)
}

func (s *stateStore) readProtected(fileName string) ([]byte, bool) {
	ciphertext, err := os.ReadFile(s.path(fileName))
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 1024*1024 {
		return nil, false
	}
	plaintext, err := winapi.Unprotect(ciphertext, s.entropy)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

func (s *stateStore) writeProtected(fileName string, plaintext []byte) error {
	ciphertext, err := winapi.Protect(plaintext, s.entropy)
	if err != nil {
		return wrapError(KindIdentity, "DPAPI protect", err)
	}
	path := s.path(fileName)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, ciphertext, 0o600); err != nil {
		return wrapError(KindIdentity, "state write", err)
	}
	if err := winapi.ReplaceFile(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return wrapError(KindIdentity, "state write", err)
	}
	return nil
}

func (s *stateStore) delete(fileName string) {
	err := os.Remove(s.path(fileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}
