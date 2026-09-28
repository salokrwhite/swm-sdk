#pragma once

#include "internal/crypto.hpp"
#include "swm/types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace swm::internal {

struct Rim2File {
    std::string path;
    std::uint64_t size = 0;
    std::array<std::uint8_t, 32> sha256{};
};

struct Rim2Manifest {
    Bytes raw;
    std::string manifest_sha256;
    std::string app_id;
    std::string release_id;
    std::uint64_t version_code = 0;
    std::string version;
    std::string arch;
    std::string root_key_id;
    std::string signer_key_id;
    std::vector<Rim2File> files;
};

Rim2Manifest parse_rim2(std::span<const std::uint8_t> manifest,
    std::string_view expected_app_id,
    std::string_view expected_release_id,
    std::string_view expected_version,
    std::optional<int> expected_version_code,
    std::string_view expected_arch,
    std::string_view expected_root_key_id,
    std::string_view root_trust_public_key);

} // namespace swm::internal
