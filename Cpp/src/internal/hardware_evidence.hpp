#pragma once

#include "swm/types.hpp"

#include <string>

namespace swm::internal {

struct HardwareFingerprint {
    std::string cpu;
    std::string motherboard;
    std::string bios;
    std::string disk;
    std::string mac;
};

HardwareFingerprint collect_hardware_fingerprint();
std::string read_machine_guid();
HardwareEvidence collect_hardware_evidence(std::string_view app_id);
HardwareEvidence build_hardware_evidence(std::string_view app_id,
    const HardwareFingerprint& fingerprint, std::string_view machine_guid);

} // namespace swm::internal
