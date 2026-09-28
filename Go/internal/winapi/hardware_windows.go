//go:build windows && (amd64 || 386)

package winapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	rawSMBIOSProvider         = 0x52534D42
	maximumFirmwareTableBytes = 1024 * 1024
	ioctlStorageQueryProperty = 0x002D1400
	storageDeviceProperty     = 0
	propertyStandardQuery     = 0
)

// HardwareEvidence mirrors device_hardware_evidence_v2.
type HardwareEvidence struct {
	Version       uint32
	ComponentMask uint32
	AggregateHash string
}

// CollectHardwareEvidence gathers the same component set used by the other
// Windows SDKs.
func CollectHardwareEvidence(appID string) (HardwareEvidence, error) {
	cpu := readCPU()
	motherboard := ""
	bios := ""
	readSMBIOS(&motherboard, &bios)
	disk := readDiskSerial()
	mac := readPhysicalMAC()
	machineGUID := readMachineGUID()
	return buildHardwareEvidence(appID, cpu, motherboard, bios, disk, mac, machineGUID)
}

func buildHardwareEvidence(appID, cpu, motherboard, bios, disk, mac, machineGUID string) (HardwareEvidence, error) {
	fields := []struct {
		bit   uint32
		name  string
		value string
	}{
		{0x01, "cpu", cpu},
		{0x02, "motherboard", motherboard},
		{0x04, "smbios", bios},
		{0x08, "disk", disk},
		{0x10, "mac", mac},
		{0x20, "machine_guid", machineGUID},
	}
	var canonical strings.Builder
	canonical.WriteString("device_hardware_evidence_v2\n")
	canonical.WriteString("app_id:")
	canonical.WriteString(appID)
	canonical.WriteByte('\n')
	var mask uint32
	for _, field := range fields {
		normalized := normalizeEvidenceValue(field.value)
		if normalized == "" {
			continue
		}
		mask |= field.bit
		canonical.WriteString(field.name)
		canonical.WriteByte(':')
		canonical.WriteString(normalized)
		canonical.WriteByte('\n')
	}
	if mask == 0 {
		return HardwareEvidence{}, fmt.Errorf("device hardware evidence collection failed")
	}
	return HardwareEvidence{
		Version:       2,
		ComponentMask: mask,
		AggregateHash: hashHex([]byte(canonical.String())),
	}, nil
}

func readCPU() string {
	_, vendorEBX, vendorECX, vendorEDX := cpuid(0, 0)
	vendor := string([]byte{
		byte(vendorEBX), byte(vendorEBX >> 8), byte(vendorEBX >> 16), byte(vendorEBX >> 24),
		byte(vendorEDX), byte(vendorEDX >> 8), byte(vendorEDX >> 16), byte(vendorEDX >> 24),
		byte(vendorECX), byte(vendorECX >> 8), byte(vendorECX >> 16), byte(vendorECX >> 24),
	})
	maximum, _, _, _ := cpuid(0x80000000, 0)
	if maximum < 0x80000004 {
		return trimASCII(vendor) + "_"
	}
	brand := make([]byte, 48)
	for index := uint32(0); index < 3; index++ {
		eax, ebx, ecx, edx := cpuid(0x80000002+index, 0)
		offset := int(index) * 16
		binary.LittleEndian.PutUint32(brand[offset:], eax)
		binary.LittleEndian.PutUint32(brand[offset+4:], ebx)
		binary.LittleEndian.PutUint32(brand[offset+8:], ecx)
		binary.LittleEndian.PutUint32(brand[offset+12:], edx)
	}
	if terminator := bytes.IndexByte(brand, 0); terminator >= 0 {
		brand = brand[:terminator]
	}
	return trimASCII(vendor) + "_" + trimASCII(string(brand))
}

func readSMBIOS(motherboard, bios *string) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTable := kernel32.NewProc("GetSystemFirmwareTable")
	size, _, _ := getTable.Call(rawSMBIOSProvider, 0, 0, 0)
	if size == 0 || size > maximumFirmwareTableBytes {
		return
	}
	buffer := make([]byte, size)
	written, _, _ := getTable.Call(
		rawSMBIOSProvider,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		size,
	)
	if written <= 8 || written > size {
		return
	}
	tableLength := binary.LittleEndian.Uint32(buffer[4:8])
	available := uint32(written - 8)
	length := tableLength
	if length > available {
		length = available
	}
	parseSMBIOS(buffer[8:8+length], motherboard, bios)
}

func parseSMBIOS(data []byte, motherboard, bios *string) {
	offset := 0
	for offset+4 <= len(data) {
		recordType := data[offset]
		length := int(data[offset+1])
		if length < 4 || offset+length > len(data) {
			return
		}
		stringsArea := data[offset+length:]
		next := findSMBIOSEnd(stringsArea)
		if next < 0 {
			return
		}
		var stringIndex byte
		if length > 7 {
			stringIndex = data[offset+7]
		}
		value := readSMBIOSString(stringsArea[:next], stringIndex)
		switch recordType {
		case 1:
			if *bios == "" {
				*bios = firstUsable(value)
			}
		case 2:
			if *motherboard == "" {
				*motherboard = firstUsable(value)
			}
		case 127:
			return
		}
		consumed := len(stringsArea) - next
		if consumed <= 0 {
			return
		}
		offset += length + consumed
	}
}

func findSMBIOSEnd(value []byte) int {
	for index := 0; index+1 < len(value); index++ {
		if value[index] == 0 && value[index+1] == 0 {
			return index + 2
		}
	}
	return -1
}

func readSMBIOSString(value []byte, index byte) string {
	if index == 0 {
		return ""
	}
	offset := 0
	for current := byte(1); current < index; current++ {
		end := bytes.IndexByte(value[offset:], 0)
		if end < 0 {
			return ""
		}
		offset += end + 1
		if offset >= len(value) {
			return ""
		}
	}
	end := bytes.IndexByte(value[offset:], 0)
	if end <= 0 {
		return ""
	}
	return string(value[offset : offset+end])
}

func readDiskSerial() string {
	for index := 0; index < 8; index++ {
		path, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, index))
		handle, err := windows.CreateFile(
			path,
			0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil {
			continue
		}
		input := make([]byte, 12)
		binary.LittleEndian.PutUint32(input[0:4], storageDeviceProperty)
		binary.LittleEndian.PutUint32(input[4:8], propertyStandardQuery)
		output := make([]byte, 4096)
		var returned uint32
		err = windows.DeviceIoControl(
			handle,
			ioctlStorageQueryProperty,
			&input[0],
			uint32(len(input)),
			&output[0],
			uint32(len(output)),
			&returned,
			nil,
		)
		_ = windows.CloseHandle(handle)
		if err != nil || returned < 36 {
			continue
		}
		busType := binary.LittleEndian.Uint32(output[28:32])
		if busType == 7 || busType == 8 || busType == 12 || busType == 13 {
			continue
		}
		serialOffset := int32(binary.LittleEndian.Uint32(output[24:28]))
		if serialOffset <= 0 || uint32(serialOffset) >= returned {
			continue
		}
		end := bytes.IndexByte(output[serialOffset:returned], 0)
		if end < 0 {
			end = int(returned - uint32(serialOffset))
		}
		if value := firstUsable(string(output[serialOffset : serialOffset+int32(end)])); value != "" {
			return value
		}
	}
	return ""
}

func readPhysicalMAC() string {
	size := uint32(15 * 1024)
	for attempts := 0; attempts < 3; attempts++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|
				windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0,
			first,
			&size,
		)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return ""
		}
		var addresses [][]byte
		for current := first; current != nil; current = current.Next {
			if current.OperStatus != windows.IfOperStatusUp ||
				(current.IfType != windows.IF_TYPE_ETHERNET_CSMACD && current.IfType != windows.IF_TYPE_IEEE80211) {
				continue
			}
			description := strings.ToLower(windows.UTF16PtrToString(current.Description))
			if containsVirtualAdapter(description) {
				continue
			}
			if current.PhysicalAddressLength != 6 {
				continue
			}
			address := append([]byte(nil), current.PhysicalAddress[:6]...)
			if bytes.Equal(address, []byte{0, 0, 0, 0, 0, 0}) || address[0]&0x02 != 0 {
				continue
			}
			addresses = append(addresses, address)
		}
		sort.Slice(addresses, func(i, j int) bool { return bytes.Compare(addresses[i], addresses[j]) < 0 })
		if len(addresses) == 0 {
			return ""
		}
		return fmt.Sprintf(
			"%02x:%02x:%02x:%02x:%02x:%02x",
			addresses[0][0], addresses[0][1], addresses[0][2],
			addresses[0][3], addresses[0][4], addresses[0][5],
		)
	}
	return ""
}

func containsVirtualAdapter(description string) bool {
	markers := []string{
		"virtual", "vmware", "vethernet", "hyper-v", "virtualbox",
		"tap-", "tap adapter", "loopback", "pseudo", "bluetooth",
		"wan miniport", "vpn", "docker", "npcap",
	}
	for _, marker := range markers {
		if strings.Contains(description, marker) {
			return true
		}
	}
	return false
}

func readMachineGUID() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.READ|registry.WOW64_64KEY,
	)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return value
}

var evidencePlaceholders = map[string]struct{}{
	"none": {}, "n/a": {}, "na": {}, "null": {}, "0": {}, "default string": {},
	"to be filled by o.e.m.": {}, "to be filled by oem": {}, "system serial number": {},
	"base board serial number": {}, "chassis serial number": {}, "not specified": {},
	"not available": {}, "unknown": {}, "0000000000": {}, "invalid": {}, "filled by oem": {},
}

func firstUsable(candidate string) string {
	value := trimASCII(candidate)
	if len(value) > 128 {
		value = value[:128]
	}
	if isPlaceholder(value) {
		return ""
	}
	return value
}

func trimASCII(value string) string {
	start := 0
	for start < len(value) && (value[start] <= 0x20 || value[start] == 0x7f) {
		start++
	}
	end := len(value)
	for end > start && (value[end-1] <= 0x20 || value[end-1] == 0x7f) {
		end--
	}
	return value[start:end]
}

func isPlaceholder(value string) bool {
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	if strings.Trim(lower, "0 \t") == "" {
		return true
	}
	_, exists := evidencePlaceholders[lower]
	return exists
}

func normalizeEvidenceValue(value string) string {
	lower := strings.ToLower(value)
	var b strings.Builder
	for i := 0; i < len(lower); i++ {
		if lower[i] <= 0x20 || lower[i] == 0x7f {
			continue
		}
		b.WriteByte(lower[i])
	}
	return b.String()
}
