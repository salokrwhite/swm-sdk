#pragma once

#include "swm/error.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace swm {

using Json = nlohmann::json;
using Bytes = std::vector<std::uint8_t>;
using StringMap = std::map<std::string, std::string, std::less<>>;

struct HostIntegrityOptions {
    bool enabled = false;
    std::filesystem::path package_root;
    std::filesystem::path manifest_path = "release-integrity.v2";
    std::function<Json(const Json& context)> evidence_provider;
};

struct ClientOptions {
    std::string base_url;
    std::string web_base_url;
    std::string app_id;
    std::string release_id;
    std::string version;
    std::optional<int> version_code;
    std::string root_trust_key_id;
    std::string root_trust_public_key;
    std::string channel = "stable";
    std::string platform = "windows";
    std::string arch;
    std::string device_id;
    std::filesystem::path storage_directory;
    bool allow_insecure_http = false;
    HostIntegrityOptions host_integrity;
};

struct HardwareEvidence {
    std::uint32_t version = 2;
    std::uint32_t component_mask = 0;
    std::string aggregate_hash;
};

struct IntegrityEvidence {
    std::string state;
    std::string failure_code;
    std::optional<std::uint32_t> evidence_version;
    std::string manifest_sha256;
    StringMap files;
};

struct MaintenanceInfo {
    bool enabled = false;
    std::string start_at;
    std::string message;
    bool active = false;
};

struct UpdateInfo {
    bool update_available = false;
    bool mandatory = false;
    int heartbeat_interval_seconds = 0;
    bool open_in_browser = false;
    std::string delivery_method;
    std::string release_id;
    std::string version;
    std::optional<int> version_code;
    std::string notes;
    std::string download_url;
    std::string checksum_sha256;
    std::string signature;
    std::string manifest_key_id;
    std::string manifest_public_key;
    std::string root_trust_key_id;
    std::string root_trust_signature;
    std::string artifact_file_name;
    std::string artifact_platform;
    std::string artifact_arch;
    std::string authz_protocol;
    bool host_integrity_required = false;
    std::int64_t size = 0;
    bool rollback_allowed = false;
    std::optional<MaintenanceInfo> maintenance;
};

struct HeartbeatResult {
    bool ok = false;
    std::string server_time;
    std::optional<MaintenanceInfo> maintenance;
};

struct Event {
    std::string device_id;
    std::string event_name;
    std::string event_time;
    std::string channel_code;
    Json properties = Json::object();
    Json attributes = Json::object();
};

struct FeedbackRequest {
    std::string content;
    std::optional<int> rating;
    std::string contact;
    std::string app_version;
    std::vector<std::filesystem::path> attachments;
    Json metadata = Json::object();
};

struct FeedbackResult {
    bool ok = false;
    std::string id;
};

struct EnrollmentTicket {
    std::string ticket;
    std::int64_t expires_at = 0;
    std::string audience;
};

struct DeviceKeyRotationResult {
    std::string registration_id;
    std::string install_id;
    std::string key_id;
    std::string device_id;
};

struct OperationAuthorizationRequest {
    std::string operation;
    Bytes plan;
    std::uint32_t step_count = 0;
    std::uint64_t total_bytes = 0;
    std::string consumer_module;
    Bytes consumer_challenge;
    std::filesystem::path host_executable_path;
    std::filesystem::path consumer_module_path;
};

struct OperationGrant {
    std::string schema;
    std::string app_id;
    std::string release_id;
    std::string device_id;
    std::string device_key_id;
    std::string key_thumbprint;
    std::string device_public_key;
    std::string authz_public_key;
    std::string authz_key_id;
    std::string authz_root_trust_key_id;
    std::string authz_root_trust_signature;
    std::string session;
    std::string grant_id;
    std::string operation;
    std::string plan_sha256;
    std::uint32_t step_count = 0;
    std::uint64_t total_bytes = 0;
    std::int64_t issued_at = 0;
    std::int64_t expires_at = 0;
    std::string consumer_challenge;
    std::string integrity_manifest_sha256;
    std::string host_exe_sha256;
    std::string consumer_module;
    std::string consumer_module_sha256;
};

struct OperationConsumptionReceipt {
    std::string schema;
    std::string grant_id;
    std::string operation;
    std::string plan_sha256;
    std::uint32_t step_count = 0;
    std::uint64_t total_bytes = 0;
    std::string consumer_challenge;
    std::int64_t consumed_at = 0;
    std::int64_t expires_at = 0;
    std::string integrity_manifest_sha256;
    std::string host_exe_sha256;
    std::string consumer_module;
    std::string consumer_module_sha256;
};

struct UpdateEvent {
    std::string id;
    std::string event_type;
    std::string org_id;
    std::string app_id;
    std::string device_id;
    std::string channel_code;
    std::string platform;
    std::string arch;
    std::string release_id;
    std::string published_at;
    std::string reason;
    std::string message;
    std::string maintenance_start_at;
};

struct UpdateStreamOptions {
    std::string current_version;
    std::optional<int> version_code;
    bool reconnect = true;
    std::chrono::milliseconds reconnect_backoff{1500};
    std::chrono::milliseconds reconnect_max_backoff{20000};
    bool jitter = true;
};

struct DebugRequestTicket {
    std::string request_id;
    std::string watch_token;
    std::int64_t expires_at = 0;
};

struct DebugDecisionEvent {
    std::string state;
    std::string reason;
    std::int64_t authorization_expires_at = 0;
};

} // namespace swm
