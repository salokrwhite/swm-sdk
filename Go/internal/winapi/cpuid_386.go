//go:build windows && 386

package winapi

//go:noescape
func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)
