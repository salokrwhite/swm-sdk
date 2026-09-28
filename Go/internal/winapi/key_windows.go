//go:build windows

package winapi

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ncryptAllowSigningFlag = 0x00000002
	ncryptSilentFlag       = 0x00000040
)

var (
	ncryptDLL = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = ncryptDLL.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
)

// IdentityKey wraps a persisted Microsoft Software KSP P-256 signing key.
type IdentityKey struct {
	mu     sync.Mutex
	handle uintptr
	name   string
}

// CreateIdentityKey creates a non-exportable P-256 key.
func CreateIdentityKey(name string) (*IdentityKey, error) {
	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(provider)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	algorithm, err := windows.UTF16PtrFromString("ECDSA_P256")
	if err != nil {
		return nil, err
	}
	var key uintptr
	if err := ncryptCall(
		procNCryptCreatePersistedKey,
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0,
	); err != nil {
		return nil, err
	}
	created := true
	defer func() {
		if created {
			_ = deleteObject(key)
		}
	}()
	if err := setDWORDProperty(key, "Key Usage", ncryptAllowSigningFlag); err != nil {
		return nil, err
	}
	if err := setDWORDProperty(key, "Export Policy", 0); err != nil {
		return nil, err
	}
	if err := ncryptCall(procNCryptFinalizeKey, key, 0); err != nil {
		return nil, err
	}
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(algorithm)
	created = false
	return &IdentityKey{handle: key, name: name}, nil
}

// OpenIdentityKey opens a persisted P-256 key by name.
func OpenIdentityKey(name string) (*IdentityKey, error) {
	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(provider)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var key uintptr
	if err := ncryptCall(
		procNCryptOpenKey,
		provider,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0,
	); err != nil {
		return nil, err
	}
	runtime.KeepAlive(namePtr)
	return &IdentityKey{handle: key, name: name}, nil
}

// Name returns the CNG persisted key name.
func (k *IdentityKey) Name() string {
	if k == nil {
		return ""
	}
	return k.name
}

// PublicKeySEC1 exports the uncompressed SEC1 P-256 public key.
func (k *IdentityKey) PublicKeySEC1() ([]byte, error) {
	if k == nil || k.handle == 0 {
		return nil, fmt.Errorf("device key is closed")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	blobType, err := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	if err != nil {
		return nil, err
	}
	var size uint32
	if err := ncryptCall(
		procNCryptExportKey,
		k.handle,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	); err != nil {
		return nil, err
	}
	if size < 8 || size > 1024 {
		return nil, fmt.Errorf("CNG returned an invalid public-key blob size")
	}
	blob := make([]byte, size)
	if err := ncryptCall(
		procNCryptExportKey,
		k.handle,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(len(blob)),
		uintptr(unsafe.Pointer(&size)),
		0,
	); err != nil {
		return nil, err
	}
	blob = blob[:size]
	if len(blob) < 8+64 {
		return nil, fmt.Errorf("CNG public-key blob is truncated")
	}
	cbKey := *(*uint32)(unsafe.Pointer(&blob[4]))
	if cbKey != 32 || len(blob) < int(8+2*cbKey) {
		return nil, fmt.Errorf("CNG key is not P-256")
	}
	sec1 := make([]byte, 65)
	sec1[0] = 0x04
	copy(sec1[1:33], blob[8:40])
	copy(sec1[33:], blob[40:72])
	runtime.KeepAlive(blobType)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(k)
	return sec1, nil
}

// SignDigest signs a SHA-256 digest and returns a 64-byte P1363 signature.
func (k *IdentityKey) SignDigest(digest []byte) ([]byte, error) {
	if k == nil || k.handle == 0 {
		return nil, fmt.Errorf("device key is closed")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("CNG digest must be 32 bytes")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var size uint32
	if err := ncryptCall(
		procNCryptSignHash,
		k.handle,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		ncryptSilentFlag,
	); err != nil {
		return nil, err
	}
	if size != 64 {
		return nil, fmt.Errorf("CNG returned an invalid P-256 signature size: %d", size)
	}
	signature := make([]byte, size)
	if err := ncryptCall(
		procNCryptSignHash,
		k.handle,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(len(signature)),
		uintptr(unsafe.Pointer(&size)),
		ncryptSilentFlag,
	); err != nil {
		return nil, err
	}
	runtime.KeepAlive(digest)
	runtime.KeepAlive(signature)
	return signature, nil
}

// Delete removes the persisted CNG key.
func (k *IdentityKey) Delete() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.handle == 0 {
		return nil
	}
	err := deleteObject(k.handle)
	k.handle = 0
	return err
}

// Close releases the CNG key handle without deleting the persisted key.
func (k *IdentityKey) Close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.handle == 0 {
		return nil
	}
	freeObject(k.handle)
	k.handle = 0
	return nil
}

func openProvider() (uintptr, error) {
	providerName, err := windows.UTF16PtrFromString("Microsoft Software Key Storage Provider")
	if err != nil {
		return 0, err
	}
	var provider uintptr
	if err := ncryptCall(
		procNCryptOpenStorageProvider,
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(providerName)),
		0,
	); err != nil {
		return 0, err
	}
	runtime.KeepAlive(providerName)
	return provider, nil
}

func setDWORDProperty(object uintptr, name string, value uint32) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	bytes := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&bytes[0])) = value
	err = ncryptCall(
		procNCryptSetProperty,
		object,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
		0,
	)
	runtime.KeepAlive(namePtr)
	runtime.KeepAlive(bytes)
	return err
}

func deleteObject(handle uintptr) error {
	if handle == 0 {
		return nil
	}
	return ncryptCall(procNCryptDeleteKey, handle, 0)
}

func freeObject(handle uintptr) {
	if handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(handle)
	}
}

func ncryptCall(proc *windows.LazyProc, args ...uintptr) error {
	result, _, callErr := proc.Call(args...)
	if result == 0 {
		return nil
	}
	if callErr != windows.ERROR_SUCCESS {
		return callErr
	}
	return windows.Errno(result)
}
