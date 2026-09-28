//go:build windows

package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protect encrypts plaintext for the current Windows user with DPAPI.
func Protect(plaintext, entropy []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("DPAPI plaintext is empty")
	}
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var optionalEntropy *windows.DataBlob
	if len(entropy) > 0 {
		optionalEntropy = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var output windows.DataBlob
	if err := windows.CryptProtectData(
		&input, nil, optionalEntropy, 0, nil, 0, &output,
	); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Data == nil || output.Size == 0 {
		return nil, fmt.Errorf("DPAPI returned an empty ciphertext")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

// Unprotect decrypts a current-user DPAPI ciphertext.
func Unprotect(ciphertext, entropy []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("DPAPI ciphertext is empty")
	}
	input := windows.DataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	var optionalEntropy *windows.DataBlob
	if len(entropy) > 0 {
		optionalEntropy = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(
		&input, nil, optionalEntropy, 0, nil, 0, &output,
	); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Data == nil || output.Size == 0 {
		return nil, fmt.Errorf("DPAPI returned empty plaintext")
	}
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}
