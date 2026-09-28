#include "internal/state_store.hpp"
#include "internal/crypto.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dpapi.h>
#include <shlobj.h>

#include <fstream>

namespace swm::internal {

StateStore::StateStore(std::string app_id, std::filesystem::path override_directory)
    : app_id_(std::move(app_id)) {
    if (app_id_.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "AppId is required");
    }
    const auto app_hash = sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(app_id_.data()), app_id_.size()));
    const auto app_hash_hex = hex_lower(app_hash);
    if (override_directory.empty()) {
        std::array<wchar_t, MAX_PATH> local_app_data{};
        if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, nullptr,
                SHGFP_TYPE_CURRENT, local_app_data.data()) != S_OK) {
            throw Error(ErrorKind::Identity, 0, {}, "cannot resolve LocalAppData");
        }
        directory_ = std::filesystem::path(local_app_data.data()) / L"SwmSdk" /
            app_hash_hex.substr(0, 12);
    } else {
        directory_ = std::filesystem::absolute(std::move(override_directory));
    }
    std::error_code error;
    std::filesystem::create_directories(directory_, error);
    if (error) {
        throw Error(ErrorKind::Identity, 0, {}, "cannot create SDK state directory");
    }
    const auto material = "SwmSdkStateV2\n" + app_id_;
    const auto digest = sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(material.data()), material.size()));
    entropy_.assign(digest.begin(), digest.end());
}

std::filesystem::path StateStore::path(const std::string_view name) const {
    return directory_ / utf8_to_wide(name);
}

std::optional<Bytes> StateStore::read_protected(const std::string_view name) const {
    std::ifstream stream(path(name), std::ios::binary | std::ios::ate);
    if (!stream) {
        return std::nullopt;
    }
    const auto end = stream.tellg();
    if (end <= 0 || end > 1024 * 1024) {
        return std::nullopt;
    }
    Bytes ciphertext(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(ciphertext.data()), end)) {
        return std::nullopt;
    }
    DATA_BLOB input{static_cast<DWORD>(ciphertext.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(ciphertext.data()))};
    DATA_BLOB entropy{static_cast<DWORD>(entropy_.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(entropy_.data()))};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return std::nullopt;
    }
    Bytes plaintext(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return plaintext;
}

void StateStore::write_protected(const std::string_view name,
    const std::span<const std::uint8_t> plaintext) const {
    DATA_BLOB input{static_cast<DWORD>(plaintext.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(plaintext.data()))};
    DATA_BLOB entropy{static_cast<DWORD>(entropy_.size()),
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(entropy_.data()))};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"SwmSdk", &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        throw Error(ErrorKind::Identity, 0, {}, "DPAPI protection failed");
    }
    Bytes ciphertext(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);

    auto target = path(name);
    auto temporary = target;
    temporary += L".tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream || !stream.write(reinterpret_cast<const char*>(ciphertext.data()),
                static_cast<std::streamsize>(ciphertext.size()))) {
            throw Error(ErrorKind::Identity, 0, {}, "cannot write SDK state");
        }
    }
    if (!MoveFileExW(temporary.c_str(), target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(temporary);
        throw Error(ErrorKind::Identity, 0, {}, "cannot commit SDK state");
    }
}

void StateStore::erase(const std::string_view name) const {
    std::error_code error;
    std::filesystem::remove(path(name), error);
}

} // namespace swm::internal
