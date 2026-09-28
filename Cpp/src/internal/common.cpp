#include "internal/common.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <stdexcept>

namespace swm::internal {

std::string hex_lower(const std::span<const std::uint8_t> value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output(value.size() * 2, '\0');
    for (std::size_t index = 0; index < value.size(); ++index) {
        output[index * 2] = digits[value[index] >> 4];
        output[index * 2 + 1] = digits[value[index] & 0x0f];
    }
    return output;
}

Bytes hex_decode(const std::string_view value) {
    if (value.size() % 2 != 0) {
        throw Error(ErrorKind::Configuration, 0, {}, "invalid hex value");
    }
    Bytes output(value.size() / 2);
    for (std::size_t index = 0; index < output.size(); ++index) {
        unsigned byte = 0;
        const auto part = value.substr(index * 2, 2);
        const auto result = std::from_chars(part.data(), part.data() + part.size(), byte, 16);
        if (result.ec != std::errc{} || result.ptr != part.data() + part.size()) {
            throw Error(ErrorKind::Configuration, 0, {}, "invalid hex value");
        }
        output[index] = static_cast<std::uint8_t>(byte);
    }
    return output;
}

std::string base64url_encode(const std::span<const std::uint8_t> value) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((value.size() + 2) / 3 * 4);
    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const auto byte : value) {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output.push_back(alphabet[(accumulator >> bits) & 0x3f]);
        }
    }
    if (bits > 0) {
        output.push_back(alphabet[(accumulator << (6 - bits)) & 0x3f]);
    }
    return output;
}

Bytes base64url_decode(const std::string_view value) {
    static constexpr std::array<std::int8_t, 256> table = [] {
        std::array<std::int8_t, 256> result{};
        result.fill(-1);
        const std::string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (std::size_t index = 0; index < alphabet.size(); ++index) {
            result[static_cast<unsigned char>(alphabet[index])] = static_cast<std::int8_t>(index);
        }
        result[static_cast<unsigned char>('+')] = 62;
        result[static_cast<unsigned char>('/')] = 63;
        return result;
    }();
    Bytes output;
    output.reserve(value.size() * 3 / 4 + 2);
    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const auto character : value) {
        if (character == '=') {
            break;
        }
        const auto decoded = table[static_cast<unsigned char>(character)];
        if (decoded < 0) {
            throw Error(ErrorKind::Configuration, 0, {}, "invalid base64url value");
        }
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(decoded);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xff));
        }
    }
    return output;
}

Bytes decode_key_material(const std::string_view value) {
    const auto cleaned = trim_ascii(std::string(value));
    if (cleaned.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "empty key material");
    }
    if (cleaned.size() % 2 == 0 &&
        std::all_of(cleaned.begin(), cleaned.end(), [](const char character) {
            return std::isxdigit(static_cast<unsigned char>(character)) != 0;
        })) {
        return hex_decode(cleaned);
    }
    return base64url_decode(cleaned);
}

std::string wide_to_utf8(const std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw Error(ErrorKind::Identity, 0, {}, "UTF-16 to UTF-8 conversion failed");
    }
    std::string output(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), output.data(), size, nullptr, nullptr);
    return output;
}

std::wstring utf8_to_wide(const std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        throw Error(ErrorKind::Identity, 0, {}, "UTF-8 to UTF-16 conversion failed");
    }
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), output.data(), size);
    return output;
}

std::string trim_ascii(std::string value) {
    const auto is_space = [](const unsigned char character) {
        return character <= 0x20 || character == 0x7f;
    };
    std::size_t begin = 0;
    while (begin < value.size() && is_space(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    std::size_t end = value.size();
    while (end > begin && is_space(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string random_uuid() {
    auto bytes = random_bytes(16);
    bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U);
    const auto hex = hex_lower(bytes);
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) +
        "-" + hex.substr(16, 4) + "-" + hex.substr(20);
}

Bytes random_bytes(const std::size_t size) {
    Bytes output(size);
    if (size > 0 && BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(size),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw Error(ErrorKind::Cryptographic, 0, {}, "random generation failed");
    }
    return output;
}

std::string json_string(const Json& value) {
    return value.dump();
}

namespace {

void skip_json_whitespace(const std::string_view value, std::size_t& offset) {
    while (offset < value.size() &&
        (value[offset] == ' ' || value[offset] == '\t' ||
            value[offset] == '\r' || value[offset] == '\n')) {
        ++offset;
    }
}

std::size_t scan_json_string(const std::string_view value, std::size_t offset) {
    if (offset >= value.size() || value[offset] != '"') {
        return std::string_view::npos;
    }
    ++offset;
    bool escaped = false;
    while (offset < value.size()) {
        const auto character = value[offset++];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (character == '\\') {
            escaped = true;
            continue;
        }
        if (character == '"') {
            return offset;
        }
    }
    return std::string_view::npos;
}

std::size_t scan_json_value(const std::string_view value, std::size_t offset) {
    if (offset >= value.size()) {
        return std::string_view::npos;
    }
    if (value[offset] == '"') {
        return scan_json_string(value, offset);
    }
    if (value[offset] != '{' && value[offset] != '[') {
        while (offset < value.size() && value[offset] != ',' && value[offset] != '}') {
            ++offset;
        }
        while (offset > 0 &&
            (value[offset - 1] == ' ' || value[offset - 1] == '\t' ||
                value[offset - 1] == '\r' || value[offset - 1] == '\n')) {
            --offset;
        }
        return offset;
    }

    std::vector<char> closing;
    while (offset < value.size()) {
        const auto character = value[offset];
        if (character == '"') {
            const auto end = scan_json_string(value, offset);
            if (end == std::string_view::npos) {
                return std::string_view::npos;
            }
            offset = end;
            continue;
        }
        if (character == '{' || character == '[') {
            closing.push_back(character == '{' ? '}' : ']');
            ++offset;
            continue;
        }
        if (character == '}' || character == ']') {
            if (closing.empty() || closing.back() != character) {
                return std::string_view::npos;
            }
            closing.pop_back();
            ++offset;
            if (closing.empty()) {
                return offset;
            }
            continue;
        }
        ++offset;
    }
    return std::string_view::npos;
}

} // namespace

Json parse_json(const std::string_view value, const std::string_view context) {
    try {
        return Json::parse(value.begin(), value.end(), nullptr, true, true);
    } catch (const std::exception& exception) {
        throw Error(ErrorKind::Protocol, 0, {}, std::string(context) + ": " + exception.what());
    }
}

std::optional<Bytes> extract_json_member_raw(const std::string_view document,
    const std::string_view member) {
    std::size_t offset = 0;
    skip_json_whitespace(document, offset);
    if (offset >= document.size() || document[offset] != '{') {
        return std::nullopt;
    }
    ++offset;
    while (true) {
        skip_json_whitespace(document, offset);
        if (offset >= document.size()) {
            return std::nullopt;
        }
        if (document[offset] == '}') {
            return std::nullopt;
        }
        const auto key_begin = offset;
        const auto key_end = scan_json_string(document, key_begin);
        if (key_end == std::string_view::npos) {
            return std::nullopt;
        }
        std::string key;
        try {
            key = Json::parse(document.substr(key_begin, key_end - key_begin))
                .get<std::string>();
        } catch (...) {
            return std::nullopt;
        }
        offset = key_end;
        skip_json_whitespace(document, offset);
        if (offset >= document.size() || document[offset] != ':') {
            return std::nullopt;
        }
        ++offset;
        skip_json_whitespace(document, offset);
        const auto value_begin = offset;
        const auto value_end = scan_json_value(document, value_begin);
        if (value_end == std::string_view::npos || value_end < value_begin) {
            return std::nullopt;
        }
        if (key == member) {
            return Bytes(document.begin() + static_cast<std::ptrdiff_t>(value_begin),
                document.begin() + static_cast<std::ptrdiff_t>(value_end));
        }
        offset = value_end;
        skip_json_whitespace(document, offset);
        if (offset >= document.size()) {
            return std::nullopt;
        }
        if (document[offset] == ',') {
            ++offset;
            continue;
        }
        if (document[offset] == '}') {
            return std::nullopt;
        }
        return std::nullopt;
    }
}

std::string json_get_string(const Json& value, const std::string_view key,
    const bool required) {
    const auto iterator = value.find(key);
    if (iterator == value.end() || iterator->is_null()) {
        if (required) {
            throw Error(ErrorKind::Protocol, 0, {}, "missing JSON field: " + std::string(key));
        }
        return {};
    }
    if (!iterator->is_string()) {
        throw Error(ErrorKind::Protocol, 0, {}, "JSON field is not a string: " + std::string(key));
    }
    return iterator->get<std::string>();
}

std::int64_t json_get_int64(const Json& value, const std::string_view key,
    const std::int64_t fallback) {
    const auto iterator = value.find(key);
    if (iterator == value.end() || iterator->is_null()) {
        return fallback;
    }
    if (!iterator->is_number_integer()) {
        throw Error(ErrorKind::Protocol, 0, {}, "JSON field is not an integer: " + std::string(key));
    }
    return iterator->get<std::int64_t>();
}

std::uint64_t json_get_uint64(const Json& value, const std::string_view key,
    const std::uint64_t fallback) {
    const auto iterator = value.find(key);
    if (iterator == value.end() || iterator->is_null()) {
        return fallback;
    }
    if (!iterator->is_number_unsigned() && !iterator->is_number_integer()) {
        throw Error(ErrorKind::Protocol, 0, {}, "JSON field is not an unsigned integer: " + std::string(key));
    }
    return iterator->get<std::uint64_t>();
}

bool json_get_bool(const Json& value, const std::string_view key, const bool fallback) {
    const auto iterator = value.find(key);
    if (iterator == value.end() || iterator->is_null()) {
        return fallback;
    }
    if (!iterator->is_boolean()) {
        throw Error(ErrorKind::Protocol, 0, {}, "JSON field is not a boolean: " + std::string(key));
    }
    return iterator->get<bool>();
}

void throw_if_stopped(const std::stop_token& stop) {
    if (stop.stop_requested()) {
        throw Error(ErrorKind::Timeout, 0, "cancelled", "operation cancelled");
    }
}

void check_win32(const bool success, const std::string_view message) {
    if (!success) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            std::string(message) + ": " + std::to_string(GetLastError()));
    }
}

void check_ntstatus(const long status, const std::string_view message) {
    if (status < 0) {
        throw Error(ErrorKind::Cryptographic, 0, {}, std::string(message) +
            ": 0x" + hex_lower(std::span(reinterpret_cast<const std::uint8_t*>(&status), sizeof(status))));
    }
}

void check_hresult(const long status, const std::string_view message) {
    if (status < 0) {
        throw Error(ErrorKind::Api, 0, {}, std::string(message));
    }
}

std::string url_escape(const std::string_view value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    for (const auto character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (std::isalnum(byte) || character == '-' || character == '_' || character == '.' ||
            character == '~') {
            output.push_back(character);
        } else {
            output.push_back('%');
            output.push_back(digits[byte >> 4]);
            output.push_back(digits[byte & 0x0f]);
        }
    }
    return output;
}

std::string canonical_query(const std::string_view query) {
    if (query.empty()) {
        return {};
    }
    std::vector<std::pair<std::string, std::string>> pairs;
    std::size_t offset = 0;
    const auto value = query.front() == '?' ? query.substr(1) : query;
    while (offset <= value.size()) {
        const auto end = value.find('&', offset);
        const auto item = value.substr(offset, end == std::string_view::npos ? end : end - offset);
        if (!item.empty()) {
            const auto separator = item.find('=');
            pairs.emplace_back(
                std::string(item.substr(0, separator)),
                separator == std::string_view::npos ? std::string{} : std::string(item.substr(separator + 1)));
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1;
    }
    std::sort(pairs.begin(), pairs.end());
    std::string output;
    for (std::size_t index = 0; index < pairs.size(); ++index) {
        if (index > 0) {
            output.push_back('&');
        }
        output += url_escape(pairs[index].first);
        output.push_back('=');
        output += url_escape(pairs[index].second);
    }
    return output;
}

void secure_zero(void* data, const std::size_t size) noexcept {
    if (data != nullptr && size > 0) {
        SecureZeroMemory(data, size);
    }
}

} // namespace swm::internal
