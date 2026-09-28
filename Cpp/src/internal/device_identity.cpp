#include "internal/device_identity.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <ncrypt.h>

#include <array>
#include <fstream>
#include <string>

namespace swm::internal {
namespace {

constexpr std::string_view metadata_file = "identity.bin";

class KeyHandle final {
public:
    ~KeyHandle() {
        if (value != 0) {
            NCryptFreeObject(value);
        }
    }
    NCRYPT_KEY_HANDLE value = 0;
};

class ProviderHandle final {
public:
    ~ProviderHandle() {
        if (value != 0) {
            NCryptFreeObject(value);
        }
    }
    NCRYPT_PROV_HANDLE value = 0;
};

std::wstring build_key_name(const std::string_view app_id, const std::string_view install_id) {
    const auto app_hash = hex_lower(sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(app_id.data()), app_id.size())));
    return utf8_to_wide("SwmSdk." + app_hash.substr(0, 12) + "." + std::string(install_id));
}

DeviceIdentity create_identity(const std::string_view app_id, const StateStore& store,
    const bool reject_existing) {
    DeviceIdentity identity;
    identity.app_id_ = std::string(app_id);
    identity.state_directory_ = store.directory();
    identity.install_id_ = hex_lower(random_bytes(16));
    identity.key_name_ = wide_to_utf8(build_key_name(app_id, identity.install_id_));

    ProviderHandle provider;
    check_ntstatus(NCryptOpenStorageProvider(&provider.value, MS_KEY_STORAGE_PROVIDER, 0),
        "NCryptOpenStorageProvider");
    KeyHandle key;
    const auto key_name = utf8_to_wide(identity.key_name_);
    const auto open_status = NCryptOpenKey(provider.value, &key.value, key_name.c_str(), 0,
        NCRYPT_SILENT_FLAG);
    if (open_status >= 0) {
        if (reject_existing) {
            identity.install_id_ = hex_lower(random_bytes(16));
            identity.key_name_ = wide_to_utf8(build_key_name(app_id, identity.install_id_));
            key = {};
        } else {
            identity.provider_ = provider.value;
            provider.value = 0;
            identity.key_ = key.value;
            key.value = 0;
            return identity;
        }
    }

    check_ntstatus(NCryptCreatePersistedKey(provider.value, &key.value,
        NCRYPT_ECDSA_P256_ALGORITHM, utf8_to_wide(identity.key_name_).c_str(), 0,
        NCRYPT_SILENT_FLAG), "NCryptCreatePersistedKey");
    const DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
    const DWORD export_policy = 0;
    check_ntstatus(NCryptSetProperty(key.value, NCRYPT_KEY_USAGE_PROPERTY,
        reinterpret_cast<PBYTE>(const_cast<DWORD*>(&usage)), sizeof(usage), 0),
        "NCryptSetProperty(key usage)");
    check_ntstatus(NCryptSetProperty(key.value, NCRYPT_EXPORT_POLICY_PROPERTY,
        reinterpret_cast<PBYTE>(const_cast<DWORD*>(&export_policy)), sizeof(export_policy), 0),
        "NCryptSetProperty(export policy)");
    check_ntstatus(NCryptFinalizeKey(key.value, NCRYPT_SILENT_FLAG), "NCryptFinalizeKey");

    identity.provider_ = provider.value;
    provider.value = 0;
    identity.key_ = key.value;
    key.value = 0;
    return identity;
}

std::optional<std::pair<std::string, std::string>> read_metadata(const StateStore& store) {
    const auto plaintext = store.read_protected(metadata_file);
    if (!plaintext) {
        return std::nullopt;
    }
    const std::string text(plaintext->begin(), plaintext->end());
    const auto first = text.find('\n');
    const auto second = first == std::string::npos ? first : text.find('\n', first + 1);
    const auto third = second == std::string::npos ? second : text.find('\n', second + 1);
    if (first == std::string::npos || second == std::string::npos || third == std::string::npos ||
        text.substr(0, first) != "v2") {
        return std::nullopt;
    }
    const auto install_id = text.substr(first + 1, second - first - 1);
    const auto key_name = text.substr(second + 1, third - second - 1);
    if (install_id.size() != 32 || key_name.empty()) {
        return std::nullopt;
    }
    return std::make_pair(install_id, key_name);
}

void populate_public_identity(DeviceIdentity& identity, NCRYPT_KEY_HANDLE key) {
    DWORD size = 0;
    check_ntstatus(NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0,
        &size, 0), "NCryptExportKey(size)");
    Bytes blob(size);
    check_ntstatus(NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(),
        size, &size, 0), "NCryptExportKey");
    if (size != sizeof(BCRYPT_ECCKEY_BLOB) + 64) {
        throw Error(ErrorKind::Identity, 0, {}, "device public key length is invalid");
    }
    const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    if (header->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header->cbKey != 32) {
        throw Error(ErrorKind::Identity, 0, {}, "device key is not P-256");
    }
    std::array<std::uint8_t, 65> sec1 = {};
    sec1[0] = 4;
    std::copy(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end(), sec1.begin() + 1);
    const auto thumbprint = sha256(sec1);
    identity.public_key_sec1_ = base64url_encode(sec1);
    identity.key_thumbprint_ = base64url_encode(thumbprint);
    identity.key_id_ = "swm-device-" + identity.key_thumbprint_.substr(0, 22);
    const auto device_material = "device_credential_v2\napp_id:" + identity.app_id_ +
        "\ninstall_id:" + identity.install_id_ +
        "\nkey_thumbprint:" + identity.key_thumbprint_;
    identity.device_id_ = sha256_hex(std::span(
        reinterpret_cast<const std::uint8_t*>(device_material.data()), device_material.size()));
}

} // namespace

DeviceIdentity::DeviceIdentity(DeviceIdentity&& other) noexcept {
    *this = std::move(other);
}

DeviceIdentity& DeviceIdentity::operator=(DeviceIdentity&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    close();
    app_id_ = std::move(other.app_id_);
    install_id_ = std::move(other.install_id_);
    key_name_ = std::move(other.key_name_);
    key_id_ = std::move(other.key_id_);
    key_thumbprint_ = std::move(other.key_thumbprint_);
    public_key_sec1_ = std::move(other.public_key_sec1_);
    device_id_ = std::move(other.device_id_);
    state_directory_ = std::move(other.state_directory_);
    provider_ = other.provider_;
    key_ = other.key_;
    other.provider_ = 0;
    other.key_ = 0;
    return *this;
}

DeviceIdentity::~DeviceIdentity() {
    close();
}

DeviceIdentity DeviceIdentity::load_or_create(const std::string_view app_id,
    const StateStore& store) {
    const auto lock_name = L"Local\\SwmSdkIdentity-" +
        utf8_to_wide(hex_lower(sha256(std::span(
            reinterpret_cast<const std::uint8_t*>(app_id.data()), app_id.size()))).substr(0, 16));
    HANDLE mutex = CreateMutexW(nullptr, FALSE, lock_name.c_str());
    if (mutex == nullptr) {
        throw Error(ErrorKind::Identity, 0, {}, "cannot create identity mutex");
    }
    const auto wait = WaitForSingleObject(mutex, 30000);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
        CloseHandle(mutex);
        throw Error(ErrorKind::Identity, 0, {}, "identity mutex timeout");
    }
    try {
        if (const auto metadata = read_metadata(store)) {
            ProviderHandle provider;
            check_ntstatus(NCryptOpenStorageProvider(&provider.value, MS_KEY_STORAGE_PROVIDER, 0),
                "NCryptOpenStorageProvider");
            KeyHandle key;
            if (NCryptOpenKey(provider.value, &key.value, utf8_to_wide(metadata->second).c_str(),
                    0, NCRYPT_SILENT_FLAG) >= 0) {
                DeviceIdentity identity;
                identity.app_id_ = std::string(app_id);
                identity.state_directory_ = store.directory();
                identity.install_id_ = metadata->first;
                identity.key_name_ = metadata->second;
                identity.provider_ = provider.value;
                provider.value = 0;
                identity.key_ = key.value;
                key.value = 0;
                populate_public_identity(identity, identity.key_);
                ReleaseMutex(mutex);
                CloseHandle(mutex);
                return identity;
            }
        }

        auto identity = create_identity(app_id, store, false);
        populate_public_identity(identity, identity.key_);
        const auto plaintext = "v2\n" + identity.install_id_ + "\n" + identity.key_name_ + "\n";
        store.write_protected(metadata_file, std::span(
            reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size()));
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        return identity;
    } catch (...) {
        ReleaseMutex(mutex);
        CloseHandle(mutex);
        throw;
    }
}

DeviceIdentity DeviceIdentity::create_pending(const std::string_view app_id,
    const StateStore& store) {
    auto identity = create_identity(app_id, store, true);
    populate_public_identity(identity, identity.key_);
    return identity;
}

void DeviceIdentity::commit_pending() {
    if (key_ == 0) {
        throw Error(ErrorKind::Identity, 0, {}, "pending identity is empty");
    }
    StateStore store(app_id_, state_directory_);
    const auto plaintext = "v2\n" + install_id_ + "\n" + key_name_ + "\n";
    store.write_protected(metadata_file, std::span(
        reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size()));
}

void DeviceIdentity::delete_pending() noexcept {
    if (key_ != 0) {
        NCryptDeleteKey(key_, 0);
        key_ = 0;
    }
    if (provider_ != 0) {
        NCryptFreeObject(provider_);
        provider_ = 0;
    }
}

std::array<std::uint8_t, 64> DeviceIdentity::sign_sha256(
    const std::array<std::uint8_t, 32>& digest) const {
    if (key_ == 0) {
        throw Error(ErrorKind::Identity, 0, {}, "device key is unavailable");
    }
    std::array<std::uint8_t, 64> signature = {};
    DWORD written = 0;
    check_ntstatus(NCryptSignHash(key_, nullptr,
        const_cast<PBYTE>(digest.data()), static_cast<DWORD>(digest.size()), signature.data(),
        static_cast<DWORD>(signature.size()), &written, NCRYPT_SILENT_FLAG),
        "NCryptSignHash");
    if (written != signature.size()) {
        throw Error(ErrorKind::Identity, 0, {}, "device signature length is invalid");
    }
    return signature;
}

void DeviceIdentity::close() noexcept {
    if (key_ != 0) {
        NCryptFreeObject(key_);
        key_ = 0;
    }
    if (provider_ != 0) {
        NCryptFreeObject(provider_);
        provider_ = 0;
    }
}

} // namespace swm::internal
