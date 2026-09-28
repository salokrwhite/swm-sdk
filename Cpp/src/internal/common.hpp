#pragma once

#include "swm/error.hpp"
#include "swm/types.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace swm::internal {

std::string hex_lower(std::span<const std::uint8_t> value);
Bytes hex_decode(std::string_view value);
std::string base64url_encode(std::span<const std::uint8_t> value);
Bytes base64url_decode(std::string_view value);
Bytes decode_key_material(std::string_view value);

std::string wide_to_utf8(std::wstring_view value);
std::wstring utf8_to_wide(std::string_view value);
std::string trim_ascii(std::string value);
std::string lower_ascii(std::string value);

std::string random_uuid();
Bytes random_bytes(std::size_t size);

std::string json_string(const Json& value);
Json parse_json(std::string_view value, std::string_view context);
std::optional<Bytes> extract_json_member_raw(std::string_view document,
    std::string_view member);
std::string json_get_string(const Json& value, std::string_view key,
    bool required = true);
std::int64_t json_get_int64(const Json& value, std::string_view key,
    std::int64_t fallback = 0);
std::uint64_t json_get_uint64(const Json& value, std::string_view key,
    std::uint64_t fallback = 0);
bool json_get_bool(const Json& value, std::string_view key, bool fallback = false);

void throw_if_stopped(const std::stop_token& stop);
void check_win32(bool success, std::string_view message);
void check_ntstatus(long status, std::string_view message);
void check_hresult(long status, std::string_view message);

std::string canonical_query(std::string_view query);
std::string url_escape(std::string_view value);

void secure_zero(void* data, std::size_t size) noexcept;

} // namespace swm::internal
