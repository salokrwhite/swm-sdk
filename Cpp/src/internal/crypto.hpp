#pragma once

#include "internal/common.hpp"

#include <array>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace swm::internal {

using Digest32 = std::array<std::uint8_t, 32>;

Digest32 sha256(std::span<const std::uint8_t> value);
std::string sha256_hex(std::span<const std::uint8_t> value);
std::array<std::uint8_t, 32> sha256_file(const std::filesystem::path& path);
std::string hmac_sha256_hex(std::string_view key, std::string_view value);
Bytes hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> value);

bool ed25519_verify(std::string_view public_key, std::span<const std::uint8_t> message,
    std::string_view signature);
std::array<std::uint8_t, 32> ed25519_public_to_x25519(std::span<const std::uint8_t> public_key);
std::array<std::uint8_t, 32> x25519_shared_secret(
    std::span<const std::uint8_t> private_key,
    std::span<const std::uint8_t> public_key);

Bytes aes256_gcm_encrypt(std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> aad);

Bytes encrypt_request_body(std::string_view method, std::string_view path,
    std::string_view canonical_query, std::int64_t timestamp, std::string_view nonce,
    std::string_view app_id, std::string_view release_id, std::string_view version,
    std::string_view version_code, std::string_view online_key_id,
    std::string_view online_public_key, std::span<const std::uint8_t> plaintext);

} // namespace swm::internal
