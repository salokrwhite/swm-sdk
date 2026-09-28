//go:build windows

package winapi

import "runtime"

// Supported reports whether this build can provide the Windows security model.
func Supported() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "386"
}
