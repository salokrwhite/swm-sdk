//go:build !windows || !(amd64 || 386)

package winapi

// HardwareEvidence mirrors device_hardware_evidence_v2.
type HardwareEvidence struct {
	Version       uint32
	ComponentMask uint32
	AggregateHash string
}

// CollectHardwareEvidence is unavailable on this target.
func CollectHardwareEvidence(string) (HardwareEvidence, error) {
	return HardwareEvidence{}, ErrUnsupportedPlatform
}
