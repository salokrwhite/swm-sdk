#include "internal/host_integrity.hpp"
#include "internal/crypto.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <fstream>
#include <sstream>

namespace swm::internal {
namespace {

constexpr std::string_view policy_file = "integrity-policy.bin";

std::string join_lines(const std::vector<std::string>& lines) {
    std::string output;
    for (const auto& line : lines) {
        output += line;
        output.push_back('\n');
    }
    return output;
}

} // namespace

HostIntegrityManager::HostIntegrityManager(const ClientOptions& options,
    const StateStore& state_store)
    : options_(options), state_store_(state_store) {}

std::optional<IntegrityEvidence> HostIntegrityManager::evidence() const {
    const auto& setting = options_.host_integrity;
    if (setting.evidence_provider) {
        try {
            const auto context = Json{
                {"app_id", options_.app_id},
                {"release_id", options_.release_id},
                {"version", options_.version},
                {"version_code", options_.version_code.value_or(0)},
                {"arch", options_.arch},
                {"package_root", package_root().string()},
                {"manifest_path", setting.manifest_path.string()}
            };
            const auto result = setting.evidence_provider(context);
            IntegrityEvidence output;
            output.state = json_get_string(result, "integrity_state", false);
            output.failure_code = json_get_string(result, "integrity_failure_code", false);
            if (result.contains("integrity_evidence_version") &&
                result["integrity_evidence_version"].is_number_unsigned()) {
                output.evidence_version =
                    result["integrity_evidence_version"].get<std::uint32_t>();
            }
            output.manifest_sha256 = json_get_string(result, "integrity_manifest_sha256", false);
            if (result.contains("integrity_files") && result["integrity_files"].is_object()) {
                for (const auto& [key, value] : result["integrity_files"].items()) {
                    if (value.is_string()) {
                        output.files[key] = value.get<std::string>();
                    }
                }
            }
            return output;
        } catch (...) {
            return IntegrityEvidence{.state = "failed",
                .failure_code = "host_integrity_internal_error"};
        }
    }
    if (!setting.enabled) {
        return std::nullopt;
    }
    try {
        const auto manifest = load_manifest();
        IntegrityEvidence result;
        result.state = "verified";
        result.evidence_version = 2;
        result.manifest_sha256 = manifest.manifest_sha256;
        for (const auto& file : manifest.files) {
            const auto path = safe_join(package_root(), file.path);
            std::error_code error;
            const auto exists = std::filesystem::exists(path, error);
            if (error) {
                return IntegrityEvidence{.state = "failed",
                    .failure_code = "host_file_io_failed"};
            }
            if (!exists) {
                // The server applies the signed Release policy to this map.
                // Missing optional and ignored files are omitted; missing
                // required files are rejected by the server.
                continue;
            }
            const auto digest = hash_file(path);
            result.files[file.path] = hex_lower(digest);
        }
        return result;
    } catch (const Error& error) {
        return IntegrityEvidence{.state = "failed",
            .failure_code = error.service_code.empty() ? "host_integrity_internal_error" : error.service_code};
    }
}

IntegrityEvidence HostIntegrityManager::required_evidence() const {
    const auto result = evidence();
    if (result && result->state == "failed") {
        throw Error(ErrorKind::Integrity, 0, result->failure_code,
            "host integrity validation failed");
    }
    return result.value_or(IntegrityEvidence{});
}

std::pair<std::string, std::string> HostIntegrityManager::resolve_operation_hashes(
    const OperationAuthorizationRequest& request) const {
    if (request.host_executable_path.empty() || request.consumer_module_path.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "host and consumer paths are required");
    }
    return {hex_lower(hash_file(request.host_executable_path)),
        hex_lower(hash_file(request.consumer_module_path))};
}

std::optional<bool> HostIntegrityManager::read_cached_policy() const {
    const auto plaintext = state_store_.read_protected(policy_file);
    if (!plaintext) {
        return std::nullopt;
    }
    const std::string text(plaintext->begin(), plaintext->end());
    std::istringstream stream(text);
    std::string header;
    std::string required;
    std::string app;
    std::string release;
    std::string version_code;
    if (!std::getline(stream, header) || !std::getline(stream, required) ||
        !std::getline(stream, app) || !std::getline(stream, release) ||
        !std::getline(stream, version_code)) {
        return std::nullopt;
    }
    if (header != "SwmSdkIntegrityPolicyV1" || app != options_.app_id ||
        release != options_.release_id ||
        version_code != std::to_string(options_.version_code.value_or(0))) {
        return std::nullopt;
    }
    if (required == "1") {
        return true;
    }
    if (required == "0") {
        return false;
    }
    return std::nullopt;
}

void HostIntegrityManager::store_policy(const bool required) {
    const auto text = join_lines({
        "SwmSdkIntegrityPolicyV1",
        required ? "1" : "0",
        options_.app_id,
        options_.release_id,
        std::to_string(options_.version_code.value_or(0)),
        std::to_string(GetTickCount64())
    });
    state_store_.write_protected(policy_file, std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

Rim2Manifest HostIntegrityManager::load_manifest() const {
    if (manifest_) {
        return *manifest_;
    }
    const auto path = safe_join(package_root(), options_.host_integrity.manifest_path.string());
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_missing", "RIM2 manifest is missing");
    }
    const auto end = stream.tellg();
    if (end <= 0 || end > 64 * 1024) {
        throw Error(ErrorKind::Integrity, 0, "host_manifest_invalid", "RIM2 manifest size is invalid");
    }
    Bytes raw(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(raw.data()), end)) {
        throw Error(ErrorKind::Integrity, 0, "host_file_io_failed", "RIM2 manifest read failed");
    }
    manifest_ = parse_rim2(raw, options_.app_id, options_.release_id, options_.version,
        options_.version_code, options_.arch, options_.root_trust_key_id,
        options_.root_trust_public_key);
    manifest_sha256_ = manifest_->manifest_sha256;
    return *manifest_;
}

std::filesystem::path HostIntegrityManager::package_root() const {
    if (!options_.host_integrity.package_root.empty()) {
        return std::filesystem::absolute(options_.host_integrity.package_root);
    }
    return std::filesystem::current_path();
}

std::filesystem::path HostIntegrityManager::safe_join(const std::filesystem::path& root,
    const std::string_view relative) {
    if (relative.empty() || relative.front() == '/' || relative.front() == '\\' ||
        relative.find(':') != std::string_view::npos ||
        relative.find("..") != std::string_view::npos) {
        throw Error(ErrorKind::Integrity, 0, "host_unsafe_path", "integrity path is unsafe");
    }
    auto normalized = std::string(relative);
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    const auto path = std::filesystem::absolute(root / utf8_to_wide(normalized));
    const auto root_text = std::filesystem::absolute(root).native();
    const auto path_text = path.native();
    if (path_text.size() <= root_text.size() ||
        _wcsnicmp(path_text.c_str(), root_text.c_str(), root_text.size()) != 0) {
        throw Error(ErrorKind::Integrity, 0, "host_unsafe_path", "integrity path escapes package root");
    }
    return path;
}

std::array<std::uint8_t, 32> HostIntegrityManager::hash_file(
    const std::filesystem::path& path) {
    return sha256_file(path);
}

} // namespace swm::internal
