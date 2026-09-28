// Package swm implements the Windows desktop client protocol for Software
// Web Manager.
//
// The SDK creates a non-exportable CNG P-256 device identity, protects local
// state with DPAPI, verifies signed server responses with Authz v3, encrypts
// request bodies, verifies RIM2 release manifests, and provides secure update
// download and event-stream helpers.
//
// The package supports Windows 10 or later on x86 and x64. Other operating
// systems can compile the package, but NewClient returns ErrUnsupportedPlatform.
package swm
