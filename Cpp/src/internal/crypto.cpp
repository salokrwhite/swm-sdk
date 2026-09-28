#include "internal/crypto.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include "monocypher.h"
#include "monocypher-ed25519.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace swm::internal {
namespace {

class AlgorithmHandle final {
public:
    ~AlgorithmHandle() {
        if (value != nullptr) {
            BCryptCloseAlgorithmProvider(value, 0);
        }
    }
    BCRYPT_ALG_HANDLE value = nullptr;
};

class KeyHandle final {
public:
    ~KeyHandle() {
        if (value != nullptr) {
            BCryptDestroyKey(value);
        }
    }
    BCRYPT_KEY_HANDLE value = nullptr;
};

class HashHandle final {
public:
    ~HashHandle() {
        if (value != nullptr) {
            BCryptDestroyHash(value);
        }
    }
    BCRYPT_HASH_HANDLE value = nullptr;
};

std::string build_body_aad(std::string_view method, std::string_view path,
    std::string_view canonical_query_value, std::int64_t timestamp, std::string_view nonce,
    std::string_view app_id, std::string_view release_id, std::string_view version,
    std::string_view version_code, std::string_view online_key_id) {
    return std::string("swm-body-x25519-aes-gcm-v1\n") +
        std::string(method) + "\n" + std::string(path) + "\n" +
        std::string(canonical_query_value) + "\n\n" + std::to_string(timestamp) + "\n" +
        std::string(nonce) + "\n" + std::string(app_id) +
        "\nclient_release_id:" + std::string(release_id) +
        "\nclient_version:" + std::string(version) +
        "\nclient_version_code:" + std::string(version_code) +
        "\nauthz_capability:v3\nbody_enc:x25519-aes-gcm-v1\nkey_id:" +
        std::string(online_key_id);
}

} // namespace

Digest32 sha256(const std::span<const std::uint8_t> value) {
    Digest32 output{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    check_ntstatus(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
        "BCryptOpenAlgorithmProvider(SHA256)");
    AlgorithmHandle algorithm_scope{algorithm};
    DWORD object_size = 0;
    DWORD returned = 0;
    check_ntstatus(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0),
        "BCryptGetProperty(SHA256 object)");
    std::vector<std::uint8_t> object(object_size);
    BCRYPT_HASH_HANDLE hash = nullptr;
    check_ntstatus(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0),
        "BCryptCreateHash(SHA256)");
    HashHandle hash_scope{hash};
    if (!value.empty()) {
        check_ntstatus(BCryptHashData(hash, const_cast<PUCHAR>(value.data()),
            static_cast<ULONG>(value.size()), 0), "BCryptHashData(SHA256)");
    }
    check_ntstatus(BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0),
        "BCryptFinishHash(SHA256)");
    return output;
}

std::string sha256_hex(const std::span<const std::uint8_t> value) {
    const auto digest = sha256(value);
    return hex_lower(digest);
}

std::array<std::uint8_t, 32> sha256_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw Error(ErrorKind::Integrity, 0, "host_file_io_failed", "protected file read failed");
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    check_ntstatus(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
        "BCryptOpenAlgorithmProvider(SHA256 file)");
    AlgorithmHandle algorithm_scope{algorithm};
    DWORD object_size = 0;
    DWORD returned = 0;
    check_ntstatus(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0),
        "BCryptGetProperty(SHA256 file)");
    std::vector<std::uint8_t> object(object_size);
    BCRYPT_HASH_HANDLE hash = nullptr;
    check_ntstatus(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0),
        "BCryptCreateHash(SHA256 file)");
    HashHandle hash_scope{hash};
    std::array<std::uint8_t, 128 * 1024> buffer{};
    while (stream) {
        stream.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const auto count = stream.gcount();
        if (count > 0) {
            check_ntstatus(BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0),
                "BCryptHashData(SHA256 file)");
        }
    }
    Digest32 output{};
    check_ntstatus(BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0),
        "BCryptFinishHash(SHA256 file)");
    return output;
}

Bytes hmac_sha256(const std::span<const std::uint8_t> key,
    const std::span<const std::uint8_t> value) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    check_ntstatus(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG), "BCryptOpenAlgorithmProvider(HMAC-SHA256)");
    AlgorithmHandle algorithm_scope{algorithm};
    DWORD object_size = 0;
    DWORD returned = 0;
    check_ntstatus(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0),
        "BCryptGetProperty(HMAC object)");
    std::vector<std::uint8_t> object(object_size);
    BCRYPT_HASH_HANDLE hash = nullptr;
    check_ntstatus(BCryptCreateHash(algorithm, &hash, object.data(), object_size,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0),
        "BCryptCreateHash(HMAC)");
    HashHandle hash_scope{hash};
    if (!value.empty()) {
        check_ntstatus(BCryptHashData(hash, const_cast<PUCHAR>(value.data()),
            static_cast<ULONG>(value.size()), 0), "BCryptHashData(HMAC)");
    }
    Bytes output(32);
    check_ntstatus(BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0),
        "BCryptFinishHash(HMAC)");
    return output;
}

std::string hmac_sha256_hex(const std::string_view key, const std::string_view value) {
    return hex_lower(hmac_sha256(
        std::span(reinterpret_cast<const std::uint8_t*>(key.data()), key.size()),
        std::span(reinterpret_cast<const std::uint8_t*>(value.data()), value.size())));
}

bool ed25519_verify(const std::string_view public_key,
    const std::span<const std::uint8_t> message, const std::string_view signature) {
    const auto key = decode_key_material(public_key);
    const auto signature_bytes = decode_key_material(signature);
    if (key.size() != 32 || signature_bytes.size() != 64) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "Ed25519 key or signature length is invalid");
    }
    return crypto_ed25519_check(signature_bytes.data(), key.data(), message.data(), message.size()) == 0;
}

std::array<std::uint8_t, 32> ed25519_public_to_x25519(
    const std::span<const std::uint8_t> public_key) {
    if (public_key.size() != 32) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "Ed25519 public key length is invalid");
    }
    std::array<std::uint8_t, 32> edwards = {};
    std::copy(public_key.begin(), public_key.end(), edwards.begin());
    edwards[31] &= 0x7f;
    std::array<std::uint8_t, 32> x25519 = {};
    crypto_eddsa_to_x25519(x25519.data(), edwards.data());
    return x25519;
}

std::array<std::uint8_t, 32> x25519_shared_secret(
    const std::span<const std::uint8_t> private_key,
    const std::span<const std::uint8_t> public_key) {
    if (private_key.size() != 32 || public_key.size() != 32) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "X25519 key length is invalid");
    }
    std::array<std::uint8_t, 32> output = {};
    crypto_x25519(output.data(), private_key.data(), public_key.data());
    if (std::all_of(output.begin(), output.end(), [](const auto value) { return value == 0; })) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "X25519 shared secret is invalid");
    }
    return output;
}

Bytes aes256_gcm_encrypt(const std::span<const std::uint8_t> key,
    const std::span<const std::uint8_t> nonce,
    const std::span<const std::uint8_t> plaintext,
    const std::span<const std::uint8_t> aad) {
    if (key.size() != 32 || nonce.size() != 12 || aad.size() > MAXDWORD) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "AES-256-GCM parameters are invalid");
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    check_ntstatus(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0),
        "BCryptOpenAlgorithmProvider(AES)");
    AlgorithmHandle algorithm_scope{algorithm};
    check_ntstatus(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0), "BCryptSetProperty(AES-GCM)");
    DWORD object_size = 0;
    DWORD returned = 0;
    check_ntstatus(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0),
        "BCryptGetProperty(AES object)");
    std::vector<std::uint8_t> object(object_size);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    check_ntstatus(BCryptGenerateSymmetricKey(algorithm, &key_handle, object.data(), object_size,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0),
        "BCryptGenerateSymmetricKey");
    KeyHandle key_scope{key_handle};

    std::array<std::uint8_t, 16> tag = {};
    std::array<std::uint8_t, 16> mac_context = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication;
    BCRYPT_INIT_AUTH_MODE_INFO(authentication);
    authentication.pbNonce = const_cast<PUCHAR>(nonce.data());
    authentication.cbNonce = static_cast<ULONG>(nonce.size());
    authentication.pbAuthData = const_cast<PUCHAR>(aad.data());
    authentication.cbAuthData = static_cast<ULONG>(aad.size());
    authentication.pbTag = tag.data();
    authentication.cbTag = static_cast<ULONG>(tag.size());
    authentication.pbMacContext = mac_context.data();
    authentication.cbMacContext = static_cast<ULONG>(mac_context.size());

    Bytes output(plaintext.size() + tag.size());
    ULONG written = 0;
    const auto status = BCryptEncrypt(key_handle,
        const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
        &authentication, nullptr, 0, output.data(),
        static_cast<ULONG>(plaintext.size()), &written, 0);
    check_ntstatus(status, "BCryptEncrypt(AES-GCM)");
    std::copy(tag.begin(), tag.end(), output.begin() + written);
    return output;
}

Bytes encrypt_request_body(const std::string_view method, const std::string_view path,
    const std::string_view canonical_query_value, const std::int64_t timestamp,
    const std::string_view nonce, const std::string_view app_id,
    const std::string_view release_id, const std::string_view version,
    const std::string_view version_code, const std::string_view online_key_id,
    const std::string_view online_public_key,
    const std::span<const std::uint8_t> plaintext) {
    const auto online_key = decode_key_material(online_public_key);
    const auto server_x25519 = ed25519_public_to_x25519(online_key);
    auto ephemeral_private = random_bytes(32);
    std::array<std::uint8_t, 32> ephemeral_public = {};
    crypto_x25519_public_key(ephemeral_public.data(), ephemeral_private.data());
    const auto shared_secret = x25519_shared_secret(ephemeral_private, server_x25519);
    secure_zero(ephemeral_private.data(), ephemeral_private.size());

    const auto context = std::string("swm-body-x25519-aes-gcm-v1\napp_id:") +
        std::string(app_id) + "\nrelease_id:" + std::string(release_id) +
        "\nkey_id:" + std::string(online_key_id) + "\npublic_key:" +
        hex_lower(online_key);
    const auto salt = sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(context.data()), context.size()));
    const auto info_text = context + "\nephemeral_public:" +
        base64url_encode(ephemeral_public);
    const auto pseudo_random_key = hmac_sha256(salt,
        shared_secret);
    auto expand_input = Bytes(info_text.begin(), info_text.end());
    expand_input.push_back(1);
    const auto request_key = hmac_sha256(pseudo_random_key, expand_input);

    const auto nonce_bytes = random_bytes(12);
    const auto aad_text = build_body_aad(method, path, canonical_query_value, timestamp,
        nonce, app_id, release_id, version, version_code, online_key_id);
    const auto ciphertext = aes256_gcm_encrypt(request_key, nonce_bytes, plaintext,
        std::span(reinterpret_cast<const std::uint8_t*>(aad_text.data()), aad_text.size()));

    Bytes output;
    output.reserve(ephemeral_public.size() + nonce_bytes.size() + ciphertext.size());
    output.insert(output.end(), ephemeral_public.begin(), ephemeral_public.end());
    output.insert(output.end(), nonce_bytes.begin(), nonce_bytes.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    return output;
}

} // namespace swm::internal
