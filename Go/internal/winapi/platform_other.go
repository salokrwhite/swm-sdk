//go:build !windows

package winapi

// Supported reports whether this build can provide the Windows security model.
func Supported() bool {
	return false
}
