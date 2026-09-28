#pragma once

#include "internal/crypto.hpp"
#include "internal/state_store.hpp"

#include <array>
#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <ncrypt.h>

namespace swm::internal {

class DeviceIdentity final {
public:
    DeviceIdentity() = default;
    DeviceIdentity(const DeviceIdentity&) = delete;
    DeviceIdentity& operator=(const DeviceIdentity&) = delete;
    DeviceIdentity(DeviceIdentity&& other) noexcept;
    DeviceIdentity& operator=(DeviceIdentity&& other) noexcept;
    ~DeviceIdentity();

    static DeviceIdentity load_or_create(std::string_view app_id, const StateStore& store);
    static DeviceIdentity create_pending(std::string_view app_id, const StateStore& store);

    void commit_pending();
    void delete_pending() noexcept;
    std::array<std::uint8_t, 64> sign_sha256(
        const std::array<std::uint8_t, 32>& digest) const;

    [[nodiscard]] const std::string& install_id() const noexcept { return install_id_; }
    [[nodiscard]] const std::string& key_name() const noexcept { return key_name_; }
    [[nodiscard]] const std::string& key_id() const noexcept { return key_id_; }
    [[nodiscard]] const std::string& key_thumbprint() const noexcept { return key_thumbprint_; }
    [[nodiscard]] const std::string& public_key_sec1() const noexcept { return public_key_sec1_; }
    [[nodiscard]] const std::string& device_id() const noexcept { return device_id_; }

    // Internal implementation state. The type is not part of the public SDK ABI.
    NCRYPT_PROV_HANDLE provider_ = 0;
    NCRYPT_KEY_HANDLE key_ = 0;
    std::string app_id_;
    std::string install_id_;
    std::string key_name_;
    std::string key_id_;
    std::string key_thumbprint_;
    std::string public_key_sec1_;
    std::string device_id_;
    std::filesystem::path state_directory_;

    void close() noexcept;
};

} // namespace swm::internal
