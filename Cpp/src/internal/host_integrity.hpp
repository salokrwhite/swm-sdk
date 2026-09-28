#pragma once

#include "internal/rim2.hpp"
#include "internal/state_store.hpp"
#include "swm/types.hpp"

#include <filesystem>
#include <optional>

namespace swm::internal {

class HostIntegrityManager final {
public:
    HostIntegrityManager(const ClientOptions& options, const StateStore& state_store);

    std::optional<IntegrityEvidence> evidence() const;
    IntegrityEvidence required_evidence() const;
    std::pair<std::string, std::string> resolve_operation_hashes(
        const OperationAuthorizationRequest& request) const;
    std::optional<bool> read_cached_policy() const;
    void store_policy(bool required);
    [[nodiscard]] const std::string& current_manifest_sha256() const noexcept {
        return manifest_sha256_;
    }

private:
    Rim2Manifest load_manifest() const;
    std::filesystem::path package_root() const;
    static std::filesystem::path safe_join(const std::filesystem::path& root,
        std::string_view relative);
    static std::array<std::uint8_t, 32> hash_file(const std::filesystem::path& path);

    const ClientOptions& options_;
    const StateStore& state_store_;
    mutable std::optional<Rim2Manifest> manifest_;
    mutable std::string manifest_sha256_;
};

} // namespace swm::internal
