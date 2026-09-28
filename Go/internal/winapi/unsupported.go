package winapi

import "errors"

// ErrUnsupportedPlatform is returned by platform primitives unavailable on
// the current target.
var ErrUnsupportedPlatform = errors.New("Windows x86 or x64 platform support is required")
