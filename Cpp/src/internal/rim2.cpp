#include "internal/rim2.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <span>

namespace swm::internal {
namespace {

constexpr std::array<std::uint8_t, 8> magic = {'O', 'P', 'L', 'U', 'S', 'R', 'I', 'M'};
constexpr std::string_view manifest_domain = "OPLUS_RELEASE_MANIFEST_V2";
constexpr std::string_view key_domain = "OPLUS_RELEASE_KEY_V2";

class Reader final {
public:
    explicit Reader(const std::span<const std::uint8_t> data) : data_(data) {}

    std::uint8_t u8() {
        require(1);
        return data_[offset_++];
    }
    std::uint16_t u16() {
        require(2);
        const auto value = static_cast<std::uint16_t>((data_[offset_] << 8) | data_[offset_ + 1]);
        offset_ += 2;
        return value;
    }
    std::uint32_t u32() {
        require(4);
        std::uint32_t value = 0;
        for (int index = 0; index < 4; ++index) {
            value = (value << 8) | data_[offset_++];
        }
        return value;
    }
    std::uint64_t u64() {
        require(8);
        std::uint64_t value = 0;
        for (int index = 0; index < 8; ++index) {
            value = (value << 8) | data_[offset_++];
        }
        return value;
    }
    std::string string8() {
        const auto size = u8();
        require(size);
        std::string value(reinterpret_cast<const char*>(data_.data() + offset_), size);
        offset_ += size;
        return value;
    }
    std::string string16() {
        const auto size = u16();
        require(size);
        std::string value(reinterpret_cast<const char*>(data_.data() + offset_), size);
        offset_ += size;
        return value;
    }
    void bytes(void* output, const std::size_t size) {
        require(size);
        std::memcpy(output, data_.data() + offset_, size);
        offset_ += size;
    }
    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

private:
    void require(const std::size_t size) const {
        if (offset_ + size > data_.size()) {
            throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 manifest is truncated");
        }
    }
    std::span<const std::uint8_t> data_;
    std::size_t offset_ = 0;
};

bool safe_path(const std::string_view value) {
    if (value.empty() || value.size() > 255 || value.front() == '/' || value.back() == '/' ||
        value.find('\\') != std::string_view::npos ||
        value.find(':') != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        return false;
    }
    std::size_t offset = 0;
    while (offset <= value.size()) {
        const auto end = value.find('/', offset);
        const auto part = value.substr(offset, end == std::string_view::npos ? end : end - offset);
        if (part.empty() || part == "." || part == "..") {
            return false;
        }
        if (std::any_of(part.begin(), part.end(), [](const unsigned char character) {
                return character < 0x20 || character == 0x7f;
            })) {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1;
    }
    return true;
}

std::string guid_text(const std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 16) {
        return {};
    }
    const auto hex = hex_lower(bytes);
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) +
        "-" + hex.substr(16, 4) + "-" + hex.substr(20);
}

int arch_byte(const std::string_view arch) {
    const auto value = lower_ascii(std::string(arch));
    if (value == "x86" || value == "i386" || value == "win-x86") {
        return 1;
    }
    if (value == "x64" || value == "amd64" || value == "win-x64") {
        return 2;
    }
    return 0;
}

std::string arch_text(const int value) {
    return value == 1 ? "x86" : value == 2 ? "x64" : std::string{};
}

void append_string8(Bytes& output, const std::string_view value) {
    if (value.size() > 255) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 string is too long");
    }
    output.push_back(static_cast<std::uint8_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

} // namespace

Rim2Manifest parse_rim2(const std::span<const std::uint8_t> manifest,
    const std::string_view expected_app_id,
    const std::string_view expected_release_id,
    const std::string_view expected_version,
    const std::optional<int> expected_version_code,
    const std::string_view expected_arch,
    const std::string_view expected_root_key_id,
    const std::string_view root_trust_public_key) {
    if (manifest.empty() || manifest.size() > 64 * 1024) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 manifest size is invalid");
    }
    Reader reader(manifest);
    std::array<std::uint8_t, 8> header{};
    reader.bytes(header.data(), header.size());
    if (header != magic || reader.u16() != 2) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 manifest header is invalid");
    }
    const auto body_size = reader.u32();
    if (body_size == 0 || body_size > reader.remaining()) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 body size is invalid");
    }
    const auto body_offset = reader.offset();
    const auto body = manifest.subspan(body_offset, body_size);
    Reader body_reader(body);
    std::array<std::uint8_t, 16> app = {};
    std::array<std::uint8_t, 16> release = {};
    body_reader.bytes(app.data(), app.size());
    body_reader.bytes(release.data(), release.size());
    const auto version_code = body_reader.u64();
    const auto platform = body_reader.u8();
    const auto architecture = body_reader.u8();
    const auto version = body_reader.string16();
    const auto file_count = body_reader.u16();
    if (file_count == 0 || file_count > 255 || version.empty() || version.size() > 100) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 identity fields are invalid");
    }
    std::vector<Rim2File> files;
    std::set<std::string, std::less<>> paths;
    for (std::uint16_t index = 0; index < file_count; ++index) {
        Rim2File file;
        file.path = body_reader.string16();
        file.size = body_reader.u64();
        body_reader.bytes(file.sha256.data(), file.sha256.size());
        const auto lowered = lower_ascii(file.path);
        if (!safe_path(file.path) || file.size == 0 ||
            std::all_of(file.sha256.begin(), file.sha256.end(), [](const auto value) { return value == 0; }) ||
            !paths.insert(lowered).second) {
            throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 contains an invalid file entry");
        }
        files.push_back(std::move(file));
    }
    if (body_reader.remaining() != 0) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 body has trailing bytes");
    }

    Reader trailer(manifest.subspan(body_offset + body_size));
    const auto root_key_id = trailer.string8();
    const auto signer_key_id = trailer.string8();
    std::array<std::uint8_t, 32> signer_public = {};
    std::array<std::uint8_t, 64> root_signature = {};
    std::array<std::uint8_t, 64> manifest_signature = {};
    trailer.bytes(signer_public.data(), signer_public.size());
    trailer.bytes(root_signature.data(), root_signature.size());
    trailer.bytes(manifest_signature.data(), manifest_signature.size());
    if (trailer.remaining() != 0 || root_key_id.empty() || root_key_id.size() > 64 ||
        signer_key_id.empty() || signer_key_id.size() > 64) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 trailer is invalid");
    }

    if (guid_text(app) != expected_app_id || guid_text(release) != expected_release_id ||
        platform != 1 || architecture != arch_byte(expected_arch) ||
        version != expected_version ||
        (expected_version_code.has_value() && version_code != static_cast<std::uint64_t>(*expected_version_code)) ||
        root_key_id != expected_root_key_id) {
        throw Error(ErrorKind::Integrity, 0, "host_release_mismatch",
            "RIM2 identity does not match this release");
    }

    Bytes key_message(key_domain.begin(), key_domain.end());
    key_message.push_back(0);
    key_message.insert(key_message.end(), app.begin(), app.end());
    append_string8(key_message, root_key_id);
    append_string8(key_message, signer_key_id);
    key_message.insert(key_message.end(), signer_public.begin(), signer_public.end());
    const auto root_signature_text = base64url_encode(
        std::span(reinterpret_cast<const std::uint8_t*>(root_signature.data()), root_signature.size()));
    if (!ed25519_verify(root_trust_public_key, key_message, root_signature_text)) {
        throw Error(ErrorKind::Integrity, 0, "host_root_signature_invalid",
            "RIM2 root certificate signature is invalid");
    }

    Bytes manifest_message(manifest_domain.begin(), manifest_domain.end());
    manifest_message.push_back(0);
    manifest_message.insert(manifest_message.end(), body.begin(), body.end());
    const auto signer_public_text = base64url_encode(signer_public);
    const auto manifest_signature_text = base64url_encode(
        std::span(reinterpret_cast<const std::uint8_t*>(manifest_signature.data()),
            manifest_signature.size()));
    if (!ed25519_verify(signer_public_text, manifest_message, manifest_signature_text)) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_signature_invalid",
            "RIM2 manifest signature is invalid");
    }

    Rim2Manifest result;
    result.raw.assign(manifest.begin(), manifest.end());
    result.manifest_sha256 = sha256_hex(manifest);
    result.app_id = guid_text(app);
    result.release_id = guid_text(release);
    result.version_code = version_code;
    result.version = version;
    result.arch = arch_text(architecture);
    result.root_key_id = root_key_id;
    result.signer_key_id = signer_key_id;
    result.files = std::move(files);
    return result;
}

} // namespace swm::internal
