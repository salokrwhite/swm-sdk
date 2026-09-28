#include "swm/client.hpp"
#include "internal/crypto.hpp"
#include "internal/multipart.hpp"
#include "internal/operation.hpp"
#include "internal/request_pipeline.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace swm {
namespace {

using Bytes = swm::Bytes;
using Json = swm::Json;

Json parse_body(const internal::ProtocolResponse& response, const char* context) {
    return internal::parse_json(std::string_view(
        reinterpret_cast<const char*>(response.body.data()), response.body.size()), context);
}

Bytes json_body(const Json& value) {
    const auto text = value.dump();
    return Bytes(text.begin(), text.end());
}

std::string optional_string(const Json& value, const char* key) {
    return internal::json_get_string(value, key, false);
}

std::optional<int> optional_int(const Json& value, const char* key) {
    if (!value.contains(key) || value[key].is_null()) {
        return std::nullopt;
    }
    return value[key].get<int>();
}

bool valid_uuid(const std::string_view value) {
    if (value.size() != 36 || value[8] != '-' || value[13] != '-' ||
        value[18] != '-' || value[23] != '-') {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(value[index]))) {
            return false;
        }
    }
    return true;
}

MaintenanceInfo maintenance_from_json(const Json& value) {
    MaintenanceInfo result;
    result.enabled = internal::json_get_bool(value, "enabled", false);
    result.start_at = optional_string(value, "start_at");
    result.message = optional_string(value, "message");
    result.active = internal::json_get_bool(value, "active", false);
    return result;
}

UpdateInfo update_from_json(const Json& value) {
    UpdateInfo result;
    result.update_available = internal::json_get_bool(value, "update_available", false);
    result.mandatory = internal::json_get_bool(value, "mandatory", false);
    result.heartbeat_interval_seconds =
        static_cast<int>(internal::json_get_int64(value, "heartbeat_interval_seconds", 0));
    result.open_in_browser = internal::json_get_bool(value, "open_in_browser", false);
    result.delivery_method = optional_string(value, "delivery_method");
    result.release_id = optional_string(value, "release_id");
    result.version = optional_string(value, "version");
    result.version_code = optional_int(value, "version_code");
    result.notes = optional_string(value, "notes");
    result.download_url = optional_string(value, "download_url");
    result.checksum_sha256 = optional_string(value, "checksum_sha256");
    result.signature = optional_string(value, "signature");
    result.manifest_key_id = optional_string(value, "manifest_key_id");
    result.manifest_public_key = optional_string(value, "manifest_public_key");
    result.root_trust_key_id = optional_string(value, "root_trust_key_id");
    result.root_trust_signature = optional_string(value, "root_trust_signature");
    result.artifact_file_name = optional_string(value, "artifact_file_name");
    result.artifact_platform = optional_string(value, "artifact_platform");
    result.artifact_arch = optional_string(value, "artifact_arch");
    result.authz_protocol = optional_string(value, "authz_protocol");
    result.host_integrity_required = internal::json_get_bool(value, "host_integrity_required", false);
    result.size = static_cast<std::int64_t>(internal::json_get_uint64(value, "size", 0));
    result.rollback_allowed = internal::json_get_bool(value, "rollback_allowed", false);
    if (value.contains("maintenance") && value["maintenance"].is_object()) {
        result.maintenance = maintenance_from_json(value["maintenance"]);
    }
    return result;
}

UpdateEvent event_from_json(const Json& value) {
    UpdateEvent event;
    event.id = optional_string(value, "id");
    event.event_type = optional_string(value, "event_type");
    event.org_id = optional_string(value, "org_id");
    event.app_id = optional_string(value, "app_id");
    event.device_id = optional_string(value, "device_id");
    event.channel_code = optional_string(value, "channel_code");
    event.platform = optional_string(value, "platform");
    event.arch = optional_string(value, "arch");
    event.release_id = optional_string(value, "release_id");
    event.published_at = optional_string(value, "published_at");
    event.reason = optional_string(value, "reason");
    event.message = optional_string(value, "message");
    event.maintenance_start_at = optional_string(value, "maintenance_start_at");
    return event;
}

Json event_to_json(const Event& event, const std::string& default_device,
    const std::string& default_channel) {
    std::string event_time = event.event_time;
    if (event_time.empty()) {
        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        std::tm utc{};
        gmtime_s(&utc, &time);
        char buffer[32]{};
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
        event_time = buffer;
    }
    Json value{
        {"device_id", event.device_id.empty() ? default_device : event.device_id},
        {"event_name", event.event_name},
        {"event_time", event_time},
        {"channel_code", event.channel_code.empty() ? default_channel : event.channel_code},
        {"properties", event.properties},
        {"attributes", event.attributes}
    };
    return value;
}

void verify_artifact_manifest(const UpdateInfo& update, const ClientOptions& options) {
    if (!update.update_available || update.open_in_browser ||
        internal::lower_ascii(update.delivery_method) == "external_link") {
        return;
    }
    if (update.release_id.empty() || update.version.empty() || update.download_url.empty() ||
        update.artifact_file_name.empty() || update.manifest_key_id.empty() ||
        update.manifest_public_key.empty() || update.root_trust_key_id.empty() ||
        update.root_trust_signature.empty() || update.signature.empty() ||
        update.checksum_sha256.size() != 64 || update.size <= 0) {
        throw Error(ErrorKind::Integrity, 0, "artifact_manifest_incomplete",
            "signed artifact manifest is incomplete");
    }
    if (update.root_trust_key_id != options.root_trust_key_id) {
        throw Error(ErrorKind::Integrity, 0, "artifact_root_trust_mismatch",
            "artifact root trust key does not match SDK configuration");
    }
    const auto root_canonical = std::string("root_trust_manifest_v1\napp_id:") +
        options.app_id + "\nsigner_key_id:" + options.root_trust_key_id +
        "\nkey_id:" + update.manifest_key_id + "\npublic_key:" +
        update.manifest_public_key;
    if (!internal::ed25519_verify(options.root_trust_public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(root_canonical.data()),
                root_canonical.size()),
            update.root_trust_signature)) {
        throw Error(ErrorKind::Integrity, 0, "artifact_root_trust_invalid",
            "artifact online key root trust signature is invalid");
    }
    const auto canonical = std::string("artifact_manifest_v1\nrelease_id:") +
        update.release_id + "\nrelease_version:" + update.version +
        "\nversion_code:" +
        (update.version_code.has_value() ? std::to_string(*update.version_code) : std::string{}) +
        "\nplatform:" + internal::lower_ascii(update.artifact_platform) +
        "\narch:" + internal::lower_ascii(update.artifact_arch) +
        "\nsize:" + std::to_string(update.size) +
        "\nsha256:" + internal::lower_ascii(update.checksum_sha256) +
        "\nkey_id:" + update.manifest_key_id;
    if (!internal::ed25519_verify(update.manifest_public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(canonical.data()),
                canonical.size()),
            update.signature)) {
        throw Error(ErrorKind::Integrity, 0, "artifact_manifest_signature_invalid",
            "artifact manifest signature is invalid");
    }
}

void verify_download(const UpdateInfo& update, const std::string& actual_sha256) {
    if (internal::lower_ascii(actual_sha256) != internal::lower_ascii(update.checksum_sha256)) {
        throw Error(ErrorKind::Integrity, 0, "artifact_checksum_mismatch",
            "downloaded artifact SHA-256 does not match");
    }
    const auto canonical = std::string("artifact_manifest_v1\nrelease_id:") +
        update.release_id + "\nrelease_version:" + update.version +
        "\nversion_code:" +
        (update.version_code.has_value() ? std::to_string(*update.version_code) : std::string{}) +
        "\nplatform:" + internal::lower_ascii(update.artifact_platform) +
        "\narch:" + internal::lower_ascii(update.artifact_arch) +
        "\nsize:" + std::to_string(update.size) +
        "\nsha256:" + internal::lower_ascii(update.checksum_sha256) +
        "\nkey_id:" + update.manifest_key_id;
    if (!internal::ed25519_verify(update.manifest_public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(canonical.data()),
                canonical.size()),
            update.signature)) {
        throw Error(ErrorKind::Integrity, 0, "artifact_manifest_signature_invalid",
            "artifact manifest signature is invalid");
    }
}

} // namespace

struct Client::Impl final {
    explicit Impl(ClientOptions value)
        : options(std::move(value)), pipeline(options) {}

    ClientOptions options;
    internal::RequestPipeline pipeline;
    std::mutex debug_mutex;
    std::map<std::string, Json, std::less<>> debug_credentials;
};

struct UpdateStream::Impl final {
    std::jthread worker;
    std::atomic_bool running = false;

    explicit Impl(std::function<void(std::stop_token)> runner) {
        running = true;
        worker = std::jthread([this, runner = std::move(runner)](const std::stop_token stop) mutable {
            struct State {
                std::atomic_bool* running;
                ~State() { *running = false; }
            } state{&running};
            try {
                runner(stop);
            } catch (...) {
                // The runner is responsible for reporting its error callback.
            }
        });
    }

    void stop() noexcept {
        worker.request_stop();
        running = false;
    }
};

UpdateStream::UpdateStream() = default;
UpdateStream::~UpdateStream() = default;
UpdateStream::UpdateStream(UpdateStream&&) noexcept = default;
UpdateStream& UpdateStream::operator=(UpdateStream&&) noexcept = default;

void UpdateStream::stop() noexcept {
    if (impl_) {
        impl_->stop();
    }
}

bool UpdateStream::running() const noexcept {
    return impl_ && impl_->running.load();
}

Client::Client(ClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {
    if (impl_->options.app_id.empty() || impl_->options.release_id.empty() ||
        impl_->options.version.empty() || impl_->options.root_trust_key_id.empty() ||
        impl_->options.root_trust_public_key.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "required ClientOptions are missing");
    }
    if (!valid_uuid(impl_->options.app_id) || !valid_uuid(impl_->options.release_id)) {
        throw Error(ErrorKind::Configuration, 0, {},
            "app_id and release_id must be UUID values");
    }
    if (impl_->options.base_url.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "base_url is required");
    }
    const auto scheme_end = impl_->options.base_url.find("://");
    const auto scheme = internal::lower_ascii(scheme_end == std::string::npos
        ? std::string{} : impl_->options.base_url.substr(0, scheme_end));
    if (scheme.empty() || (scheme != "https" &&
            !(impl_->options.allow_insecure_http && scheme == "http"))) {
        throw Error(ErrorKind::Configuration, 0, {},
            "base_url must use HTTPS unless allow_insecure_http is enabled");
    }
    try {
        if (internal::decode_key_material(impl_->options.root_trust_public_key).size() != 32) {
            throw Error(ErrorKind::Configuration, 0, {},
                "root_trust_public_key must contain 32 bytes");
        }
    } catch (const Error&) {
        throw Error(ErrorKind::Configuration, 0, {},
            "root_trust_public_key is invalid");
    }
    if (impl_->options.version_code.has_value() && *impl_->options.version_code < 0) {
        throw Error(ErrorKind::Configuration, 0, {},
            "version_code cannot be negative");
    }
    if (impl_->options.arch.empty()) {
#if defined(_M_IX86)
        impl_->options.arch = "x86";
#else
        impl_->options.arch = "x64";
#endif
    }
}

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;
Client::~Client() = default;

const std::string& Client::device_id() const noexcept { return impl_->pipeline.device_id(); }
const std::string& Client::install_id() const noexcept { return impl_->pipeline.install_id(); }
const std::string& Client::device_key_id() const noexcept { return impl_->pipeline.device_key_id(); }

void Client::refresh_online_keys(const std::stop_token& stop) {
    impl_->pipeline.refresh_online_keys(true, stop);
}

AsyncTask<void> Client::refresh_online_keys_async() {
    return make_async([this](const std::stop_token stop) {
        refresh_online_keys(stop);
    });
}

UpdateInfo Client::check_update(const Json& attributes, const std::string& user_id,
    const std::stop_token& stop) {
    Json attributes_object = attributes.is_object() ? attributes : Json::object();
    Json payload{
        {"channel_code", impl_->options.channel},
        {"current_version", impl_->options.version},
        {"version_code", impl_->options.version_code},
        {"platform", impl_->options.platform},
        {"arch", impl_->options.arch},
        {"device_id", device_id()},
        {"attributes", attributes_object},
        {"device_auth", impl_->pipeline.create_device_auth()}
    };
    if (!user_id.empty()) {
        payload["user_id"] = user_id;
    }
    const auto integrity = impl_->pipeline.host_integrity().evidence();
    if (integrity) {
        payload["integrity_state"] = integrity->state;
        if (!integrity->failure_code.empty()) {
            payload["integrity_failure_code"] = integrity->failure_code;
        }
        if (integrity->evidence_version) {
            payload["integrity_evidence_version"] = *integrity->evidence_version;
        }
        if (!integrity->manifest_sha256.empty()) {
            payload["integrity_manifest_sha256"] = integrity->manifest_sha256;
        }
        if (!integrity->files.empty()) {
            payload["integrity_files"] = integrity->files;
        }
    }
    std::string challenge;
    for (int attempt = 0; attempt < 2; ++attempt) {
        auto request_body = json_body(payload);
        const auto response = impl_->pipeline.send(internal::ProtocolRequest{
            .method = "POST",
            .path = "/api/client/update-check",
            .operation = internal::OperationClass::UpdateCheck,
            .body = std::move(request_body),
            .encrypt_body = true,
            .require_session = false,
            .require_trusted_time = true,
            .require_online_key = true
        }, stop);
        if (response.status_code == 428 && attempt == 0) {
            const auto body = parse_body(response, "device registration challenge");
            challenge = internal::json_get_string(body, "challenge");
            const auto expires_at = internal::json_get_int64(body, "expires_at");
            if (challenge.empty() || expires_at <= impl_->pipeline.clock().now_unix_seconds()) {
                throw Error(ErrorKind::Protocol, 0, {}, "device registration challenge is invalid");
            }
            payload["device_auth"] = impl_->pipeline.create_device_auth(challenge);
            continue;
        }
        const auto data = impl_->pipeline.verify_authz(response);
        auto update = update_from_json(data);
        impl_->pipeline.set_host_integrity_required(update.host_integrity_required);
        verify_artifact_manifest(update, impl_->options);
        return update;
    }
    throw Error(ErrorKind::Protocol, 0, {}, "device registration challenge retry was exhausted");
}

AsyncTask<UpdateInfo> Client::check_update_async(Json attributes, std::string user_id) {
    return make_async([this, attributes = std::move(attributes),
                          user_id = std::move(user_id)](const std::stop_token stop) {
        return check_update(attributes, user_id, stop);
    });
}

HeartbeatResult Client::report_heartbeat(const std::string& app_version,
    const Json& attributes, const std::string& user_id, const std::stop_token& stop) {
    Json payload{
        {"device_id", device_id()},
        {"channel_code", impl_->options.channel},
        {"app_version", app_version.empty() ? impl_->options.version : app_version},
        {"platform", impl_->options.platform},
        {"arch", impl_->options.arch},
        {"attributes", attributes.is_object() ? attributes : Json::object()}
    };
    if (!user_id.empty()) {
        payload["user_id"] = user_id;
    }
    const auto evidence = impl_->pipeline.host_integrity_required()
        ? impl_->pipeline.host_integrity().required_evidence()
        : impl_->pipeline.host_integrity().evidence().value_or(IntegrityEvidence{});
    if (!evidence.state.empty()) {
        if (evidence.evidence_version) {
            payload["integrity_evidence_version"] = *evidence.evidence_version;
        }
        if (!evidence.manifest_sha256.empty()) {
            payload["integrity_manifest_sha256"] = evidence.manifest_sha256;
        }
        if (!evidence.files.empty()) {
            payload["integrity_files"] = evidence.files;
        }
    }
    const auto data = impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/heartbeat",
        .operation = internal::OperationClass::Heartbeat,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
    HeartbeatResult result;
    result.ok = internal::json_get_bool(data, "ok", false);
    result.server_time = optional_string(data, "server_time");
    if (data.contains("maintenance") && data["maintenance"].is_object()) {
        result.maintenance = maintenance_from_json(data["maintenance"]);
    }
    return result;
}

AsyncTask<HeartbeatResult> Client::report_heartbeat_async(std::string app_version,
    Json attributes, std::string user_id) {
    return make_async([this, app_version = std::move(app_version),
                          attributes = std::move(attributes),
                          user_id = std::move(user_id)](const std::stop_token stop) {
        return report_heartbeat(app_version, attributes, user_id, stop);
    });
}

void Client::report_event(const Event& event, const std::stop_token& stop) {
    if (internal::trim_ascii(event.event_name).empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "event_name is required");
    }
    const auto payload = event_to_json(event, device_id(), impl_->options.channel);
    impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/events",
        .operation = internal::OperationClass::Events,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
}

void Client::report_events(const std::vector<Event>& events, const std::stop_token& stop) {
    if (events.empty()) {
        return;
    }
    Json array = Json::array();
    for (const auto& event : events) {
        if (internal::trim_ascii(event.event_name).empty()) {
            throw Error(ErrorKind::Configuration, 0, {}, "event_name is required");
        }
        array.push_back(event_to_json(event, device_id(), impl_->options.channel));
    }
    const Json payload = events.size() == 1 ? array[0] : Json{{"events", array}};
    impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/events",
        .operation = internal::OperationClass::Events,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
}

AsyncTask<void> Client::report_event_async(Event event) {
    return make_async([this, event = std::move(event)](const std::stop_token stop) {
        report_event(event, stop);
    });
}

AsyncTask<void> Client::report_events_async(std::vector<Event> events) {
    return make_async([this, events = std::move(events)](const std::stop_token stop) {
        report_events(events, stop);
    });
}

FeedbackResult Client::submit_feedback(const FeedbackRequest& request,
    const std::stop_token& stop) {
    auto multipart = internal::build_feedback_payload(device_id(), impl_->options.channel,
        impl_->options.version, request);
    const auto data = impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/feedback",
        .operation = internal::OperationClass::Feedback,
        .body = std::move(multipart.body),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true,
        .content_type = multipart.content_type
    }, stop);
    const auto ok = internal::json_get_bool(data, "ok", false);
    const auto id = internal::json_get_string(data, "id");
    if (!ok || !valid_uuid(id)) {
        throw Error(ErrorKind::Protocol, 0, {},
            "feedback response is incomplete or invalid");
    }
    return FeedbackResult{.ok = true, .id = id};
}

AsyncTask<FeedbackResult> Client::submit_feedback_async(FeedbackRequest request) {
    return make_async([this, request = std::move(request)](const std::stop_token stop) {
        return submit_feedback(request, stop);
    });
}

EnrollmentTicket Client::request_enrollment_ticket(const std::string& audience,
    const std::stop_token& stop) {
    const auto normalized_audience = internal::lower_ascii(internal::trim_ascii(audience));
    if (normalized_audience.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "enrollment audience is required");
    }
    const Json payload{{"audience", normalized_audience}};
    const auto data = impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/enrollment-ticket",
        .operation = internal::OperationClass::EnrollmentTicket,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
    return EnrollmentTicket{
        .ticket = internal::json_get_string(data, "ticket"),
        .expires_at = internal::json_get_int64(data, "expires_at"),
        .audience = internal::json_get_string(data, "audience")
    };
}

AsyncTask<EnrollmentTicket> Client::request_enrollment_ticket_async(std::string audience) {
    return make_async([this, audience = std::move(audience)](const std::stop_token stop) {
        return request_enrollment_ticket(audience, stop);
    });
}

DeviceKeyRotationResult Client::rotate_device_key(const std::stop_token& stop) {
    return impl_->pipeline.rotate_device_key(stop);
}

AsyncTask<DeviceKeyRotationResult> Client::rotate_device_key_async() {
    return make_async([this](const std::stop_token stop) {
        return rotate_device_key(stop);
    });
}

OperationGrant Client::authorize_operation(const OperationAuthorizationRequest& request,
    const std::stop_token& stop) {
    if (impl_->pipeline.offline_locked()) {
        throw Error(ErrorKind::OfflineBudget, 0, "offline_budget_exceeded",
            "offline budget exceeded; restart the client and complete a full bootstrap");
    }
    const auto operation = internal::trim_ascii(request.operation);
    const auto consumer_module = internal::trim_ascii(request.consumer_module);
    const bool host_bound = internal::validate_operation_authorization_request(
        request, impl_->pipeline.host_integrity_required());
    auto challenge = request.consumer_challenge.empty()
        ? internal::random_bytes(32) : request.consumer_challenge;
    if (challenge.size() != 32) {
        throw Error(ErrorKind::Configuration, 0, {}, "consumer challenge must be 32 bytes");
    }
    const auto plan_hash = internal::sha256_hex(request.plan);
    std::string manifest_hash;
    std::string host_hash;
    std::string module_hash;
    if (host_bound) {
        const auto evidence = impl_->pipeline.host_integrity().required_evidence();
        manifest_hash = evidence.manifest_sha256;
        const auto hashes = impl_->pipeline.host_integrity().resolve_operation_hashes(request);
        host_hash = hashes.first;
        module_hash = hashes.second;
    }
    Json payload{
        {"schema", host_bound ? "operation_grant_v3_host" : "operation_grant_v3_unbound"},
        {"operation", operation},
        {"plan_sha256", plan_hash},
        {"step_count", request.step_count},
        {"total_bytes", request.total_bytes},
        {"consumer_challenge", internal::hex_lower(challenge)},
        {"consumer_module", consumer_module}
    };
    if (host_bound) {
        payload["integrity_manifest_sha256"] = manifest_hash;
        payload["host_exe_sha256"] = host_hash;
        payload["consumer_module_sha256"] = module_hash;
    }
    const auto data = impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/operation-authorizations",
        .operation = internal::OperationClass::OperationAuthorization,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
    return OperationGrant{
        .schema = internal::json_get_string(data, "schema"),
        .app_id = internal::json_get_string(data, "app_id"),
        .release_id = internal::json_get_string(data, "release_id"),
        .device_id = internal::json_get_string(data, "device_id"),
        .device_key_id = internal::json_get_string(data, "device_key_id"),
        .key_thumbprint = internal::json_get_string(data, "key_thumbprint"),
        .device_public_key = internal::json_get_string(data, "device_public_key"),
        .authz_public_key = internal::json_get_string(data, "authz_public_key"),
        .authz_key_id = internal::json_get_string(data, "authz_key_id"),
        .authz_root_trust_key_id = internal::json_get_string(data, "authz_root_trust_key_id"),
        .authz_root_trust_signature = internal::json_get_string(data, "authz_root_trust_signature"),
        .session = internal::json_get_string(data, "session"),
        .grant_id = internal::json_get_string(data, "grant_id"),
        .operation = internal::json_get_string(data, "operation"),
        .plan_sha256 = internal::json_get_string(data, "plan_sha256"),
        .step_count = static_cast<std::uint32_t>(internal::json_get_uint64(data, "step_count")),
        .total_bytes = internal::json_get_uint64(data, "total_bytes"),
        .issued_at = internal::json_get_int64(data, "issued_at"),
        .expires_at = internal::json_get_int64(data, "expires_at"),
        .consumer_challenge = internal::json_get_string(data, "consumer_challenge"),
        .integrity_manifest_sha256 = optional_string(data, "integrity_manifest_sha256"),
        .host_exe_sha256 = optional_string(data, "host_exe_sha256"),
        .consumer_module = internal::json_get_string(data, "consumer_module"),
        .consumer_module_sha256 = optional_string(data, "consumer_module_sha256")
    };
}

AsyncTask<OperationGrant> Client::authorize_operation_async(OperationAuthorizationRequest request) {
    return make_async([this, request = std::move(request)](const std::stop_token stop) {
        return authorize_operation(request, stop);
    });
}

OperationConsumptionReceipt Client::consume_operation_authorization(
    const OperationGrant& grant, const std::stop_token& stop) {
    if (impl_->pipeline.offline_locked()) {
        throw Error(ErrorKind::OfflineBudget, 0, "offline_budget_exceeded",
            "offline budget exceeded; restart the client and complete a full bootstrap");
    }
    internal::validate_operation_grant(grant);
    Json payload{
        {"schema", "operation_grant_consume_v2"},
        {"grant_id", grant.grant_id},
        {"operation", grant.operation},
        {"plan_sha256", grant.plan_sha256},
        {"step_count", grant.step_count},
        {"total_bytes", grant.total_bytes},
        {"consumer_challenge", grant.consumer_challenge},
        {"issued_at", grant.issued_at},
        {"expires_at", grant.expires_at},
        {"consumer_module", grant.consumer_module}
    };
    if (!grant.integrity_manifest_sha256.empty()) {
        payload["integrity_manifest_sha256"] = grant.integrity_manifest_sha256;
    }
    if (!grant.host_exe_sha256.empty()) {
        payload["host_exe_sha256"] = grant.host_exe_sha256;
    }
    if (!grant.consumer_module_sha256.empty()) {
        payload["consumer_module_sha256"] = grant.consumer_module_sha256;
    }
    const auto data = impl_->pipeline.send_and_verify(internal::ProtocolRequest{
        .method = "POST",
        .path = "/api/client/operation-authorizations/consume",
        .operation = internal::OperationClass::OperationGrantConsume,
        .body = json_body(payload),
        .encrypt_body = true,
        .require_session = true,
        .require_trusted_time = true,
        .require_online_key = true
    }, stop);
    return OperationConsumptionReceipt{
        .schema = internal::json_get_string(data, "schema"),
        .grant_id = internal::json_get_string(data, "grant_id"),
        .operation = internal::json_get_string(data, "operation"),
        .plan_sha256 = internal::json_get_string(data, "plan_sha256"),
        .step_count = static_cast<std::uint32_t>(internal::json_get_uint64(data, "step_count")),
        .total_bytes = internal::json_get_uint64(data, "total_bytes"),
        .consumer_challenge = internal::json_get_string(data, "consumer_challenge"),
        .consumed_at = internal::json_get_int64(data, "consumed_at"),
        .expires_at = internal::json_get_int64(data, "expires_at"),
        .integrity_manifest_sha256 = optional_string(data, "integrity_manifest_sha256"),
        .host_exe_sha256 = optional_string(data, "host_exe_sha256"),
        .consumer_module = internal::json_get_string(data, "consumer_module"),
        .consumer_module_sha256 = optional_string(data, "consumer_module_sha256")
    };
}

AsyncTask<OperationConsumptionReceipt> Client::consume_operation_authorization_async(
    OperationGrant grant) {
    return make_async([this, grant = std::move(grant)](const std::stop_token stop) {
        return consume_operation_authorization(grant, stop);
    });
}

namespace {

bool valid_download_url(const std::string& raw, const std::string& base) {
    const auto marker = raw.find("://");
    const auto base_marker = base.find("://");
    if (marker == std::string::npos || base_marker == std::string::npos ||
        raw.substr(0, marker) != base.substr(0, base_marker)) {
        return false;
    }
    const auto raw_host_begin = marker + 3;
    const auto base_host_begin = base_marker + 3;
    const auto raw_slash = raw.find('/', raw_host_begin);
    const auto base_slash = base.find('/', base_host_begin);
    if (raw_slash == std::string::npos || base_slash == std::string::npos ||
        raw.substr(raw_host_begin, raw_slash - raw_host_begin) !=
            base.substr(base_host_begin, base_slash - base_host_begin)) {
        return false;
    }
    const auto path = raw.substr(raw_slash);
    const auto query = path.find("ticket=");
    if (query == std::string::npos) {
        return false;
    }
    const auto only_path = path.substr(0, path.find('?'));
    const auto parts = [&] {
        std::vector<std::string> values;
        std::size_t offset = 1;
        while (offset <= only_path.size()) {
            const auto end = only_path.find('/', offset);
            values.push_back(only_path.substr(offset, end == std::string::npos ? end : end - offset));
            if (end == std::string::npos) {
                break;
            }
            offset = end + 1;
        }
        return values;
    }();
    return parts.size() == 5 && parts[0] == "api" && parts[1] == "client" &&
        parts[2] == "artifacts" && parts[4] == "download";
}

std::string resolve_redirect_url(const std::string& current, const std::string& raw_location) {
    const auto location = internal::trim_ascii(raw_location);
    if (location.empty()) {
        throw Error(ErrorKind::Protocol, 0, {}, "download redirect is missing Location");
    }
    if (location.find("://") != std::string::npos) {
        return location;
    }
    const auto scheme_end = current.find("://");
    if (scheme_end == std::string::npos) {
        throw Error(ErrorKind::Protocol, 0, {}, "download URL is invalid");
    }
    const auto authority_end = current.find('/', scheme_end + 3);
    const auto origin = current.substr(0,
        authority_end == std::string::npos ? current.size() : authority_end);
    if (location.starts_with("//")) {
        return current.substr(0, scheme_end + 1) + location;
    }
    if (location.starts_with("/")) {
        return origin + location;
    }
    const auto query = current.find_first_of("?#", authority_end == std::string::npos ?
        current.size() : authority_end);
    const auto path_end = query == std::string::npos ? current.size() : query;
    const auto slash = current.rfind('/', path_end);
    const auto directory = slash == std::string::npos || slash < authority_end
        ? origin + "/" : current.substr(0, slash + 1);
    return directory + location;
}

struct ContentRange {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::uint64_t total = 0;
};

std::optional<ContentRange> parse_content_range(const std::string& value) {
    const auto text = internal::trim_ascii(value);
    if (!text.starts_with("bytes ")) {
        return std::nullopt;
    }
    const auto dash = text.find('-', 6);
    const auto slash = text.find('/', dash == std::string::npos ? 6 : dash + 1);
    if (dash == std::string::npos || slash == std::string::npos) {
        return std::nullopt;
    }
    try {
        ContentRange result;
        result.start = std::stoull(text.substr(6, dash - 6));
        result.end = std::stoull(text.substr(dash + 1, slash - dash - 1));
        if (text.substr(slash + 1) != "*") {
            result.total = std::stoull(text.substr(slash + 1));
        }
        if (result.end < result.start || (result.total != 0 && result.end >= result.total)) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

Bytes read_all(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw Error(ErrorKind::Api, 0, {}, "file read failed");
    }
    return Bytes(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::string sha_file(const std::filesystem::path& path) {
    const auto data = read_all(path);
    return internal::sha256_hex(data);
}

class SseReader final {
public:
    explicit SseReader(internal::ResponseStream& stream) : stream_(stream) {}

    std::optional<std::string> read_line(const std::stop_token& stop) {
        while (true) {
            const auto end = pending_.find('\n');
            if (end != std::string::npos) {
                auto line = pending_.substr(0, end);
                pending_.erase(0, end + 1);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                return line;
            }
            std::array<std::uint8_t, 32 * 1024> buffer{};
            const auto read = stream_.read(buffer, stop);
            if (read == 0) {
                if (pending_.empty()) {
                    return std::nullopt;
                }
                auto line = pending_;
                pending_.clear();
                return line;
            }
            pending_.append(reinterpret_cast<const char*>(buffer.data()), read);
            if (pending_.size() > 256 * 1024) {
                throw Error(ErrorKind::Protocol, 0, {}, "SSE event exceeds size limit");
            }
        }
    }

private:
    internal::ResponseStream& stream_;
    std::string pending_;
};

struct ParsedSseEvent {
    std::string name;
    std::string id;
    std::string data;
};

std::optional<ParsedSseEvent> next_sse(SseReader& reader, const std::stop_token& stop) {
    std::string event_name;
    std::string event_id;
    std::string data;
    while (true) {
        const auto line = reader.read_line(stop);
        if (!line) {
            if (data.empty()) {
                return std::nullopt;
            }
            return ParsedSseEvent{event_name, event_id, data};
        }
        if (line->empty()) {
            if (!data.empty()) {
                return ParsedSseEvent{event_name, event_id, data};
            }
            event_name.clear();
            event_id.clear();
            continue;
        }
        if (line->starts_with(":")) {
            continue;
        }
        if (line->starts_with("event:")) {
            event_name = internal::trim_ascii(line->substr(6));
        } else if (line->starts_with("id:")) {
            event_id = internal::trim_ascii(line->substr(3));
        } else if (line->starts_with("data:")) {
            if (!data.empty()) {
                data.push_back('\n');
            }
            data += internal::trim_ascii(line->substr(5));
        }
    }
}

bool sleep_for_stream_backoff(const std::chrono::milliseconds delay,
    const std::stop_token& stop) {
    const auto deadline = std::chrono::steady_clock::now() + delay;
    while (!stop.stop_requested()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        std::this_thread::sleep_for(std::min(remaining, std::chrono::milliseconds(100)));
    }
    return true;
}

} // namespace

void Client::download_update(const UpdateInfo& update,
    const std::filesystem::path& destination,
    const std::function<void(std::uint64_t, std::uint64_t)>& progress,
    const std::stop_token& stop) {
    if (!update.update_available || update.open_in_browser ||
        !valid_download_url(update.download_url, impl_->options.base_url)) {
        throw Error(ErrorKind::Configuration, 0, {}, "update does not contain a valid download URL");
    }
    if (!destination.parent_path().empty()) {
        std::filesystem::create_directories(destination.parent_path());
    }
    const auto partial = destination.string() + ".part";
    auto existing = std::filesystem::exists(partial)
        ? std::filesystem::file_size(partial) : 0ULL;
    auto download_url = update.download_url;
    bool authenticated = true;
    internal::ResponseStream stream;
    for (int redirect = 0; redirect < 4; ++redirect) {
        stream = impl_->pipeline.open_download_stream(
            download_url, existing, authenticated, stop);
        if (stream.status_code() < 300 || stream.status_code() >= 400) {
            break;
        }
        const auto location = stream.headers().get("location");
        if (!location) {
            throw Error(ErrorKind::Protocol, 0, {}, "download redirect is missing Location");
        }
        download_url = resolve_redirect_url(download_url, *location);
        authenticated = false;
    }
    if (stream.status_code() >= 300 && stream.status_code() < 400) {
        throw Error(ErrorKind::Protocol, 0, {}, "download redirect limit exceeded");
    }
    if (stream.status_code() >= 400) {
        std::array<std::uint8_t, 64 * 1024> buffer{};
        const auto read = stream.read(buffer, stop);
        const auto body = std::string(reinterpret_cast<const char*>(buffer.data()), read);
        throw Error(ErrorKind::Api, stream.status_code(), {}, body);
    }
    std::uint64_t expected = 0;
    bool append = false;
    for (int range_attempt = 0; range_attempt < 2; ++range_attempt) {
        const auto content_range = stream.headers().get("content-range");
        if (stream.status_code() == 206) {
            if (!content_range) {
                throw Error(ErrorKind::Protocol, 0, {},
                    "partial download is missing Content-Range");
            }
            const auto parsed = parse_content_range(*content_range);
            if (!parsed) {
                throw Error(ErrorKind::Protocol, 0, {},
                    "partial download Content-Range is invalid");
            }
            if (parsed->start != existing) {
                if (range_attempt != 0) {
                    throw Error(ErrorKind::Protocol, 0, {},
                        "partial download range does not match the local file");
                }
                stream.close();
                existing = 0;
                stream = impl_->pipeline.open_download_stream(
                    download_url, 0, authenticated, stop);
                continue;
            }
            append = existing > 0;
            expected = parsed->total;
        } else {
            if (stream.status_code() != 200) {
                throw Error(ErrorKind::Api, stream.status_code(), {},
                    "download was rejected");
            }
            if (existing > 0) {
                append = false;
                existing = 0;
            }
        }
        break;
    }
    if (expected == 0) {
        const auto content_length = stream.headers().get("content-length");
        try {
            expected = (content_length ? std::stoull(*content_length) : 0ULL) + existing;
        } catch (...) {
            throw Error(ErrorKind::Protocol, 0, {}, "download Content-Length is invalid");
        }
    }
    std::ofstream output(partial,
        std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    if (!output) {
        throw Error(ErrorKind::Api, 0, {}, "cannot create download file");
    }
    std::array<std::uint8_t, 128 * 1024> buffer{};
    std::uint64_t written = existing;
    while (true) {
        const auto read = stream.read(buffer, stop);
        if (read == 0) {
            break;
        }
        output.write(reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(read));
        written += read;
        if (progress) {
            progress(written, expected);
        }
    }
    output.close();
    if (expected > 0 && written != expected) {
        std::filesystem::remove(partial);
        throw Error(ErrorKind::Api, 0, {}, "download length mismatch");
    }
    try {
        verify_download(update, sha_file(partial));
    } catch (...) {
        std::filesystem::remove(partial);
        throw;
    }
    std::error_code remove_error;
    std::filesystem::remove(destination, remove_error);
    std::filesystem::rename(partial, destination);
}

AsyncTask<void> Client::download_update_async(UpdateInfo update,
    std::filesystem::path destination,
    std::function<void(std::uint64_t, std::uint64_t)> progress) {
    return make_async([this, update = std::move(update), destination = std::move(destination),
                          progress = std::move(progress)](const std::stop_token stop) {
        download_update(update, destination, progress, stop);
    });
}

UpdateStream Client::watch_updates(UpdateStreamOptions options,
    UpdateStream::EventCallback on_event, UpdateStream::ErrorCallback on_error,
    UpdateStream::ControlCallback on_control) {
    auto runner = [this, options = std::move(options), on_event = std::move(on_event),
                      on_error = std::move(on_error), on_control = std::move(on_control)](
                      const std::stop_token stop) mutable {
        std::uint64_t attempt = 0;
        while (!stop.stop_requested()) {
            try {
                const auto current_version = options.current_version.empty()
                    ? impl_->options.version : options.current_version;
                const auto version_code = options.version_code.has_value()
                    ? *options.version_code : impl_->options.version_code.value_or(0);
                const auto query = std::string("device_id=") + internal::url_escape(device_id()) +
                    "&channel_code=" + internal::url_escape(impl_->options.channel) +
                    "&platform=" + internal::url_escape(impl_->options.platform) +
                    "&arch=" + internal::url_escape(impl_->options.arch) +
                    "&current_version=" + internal::url_escape(current_version) +
                    "&version_code=" + std::to_string(version_code);
                auto base = impl_->options.base_url;
                while (!base.empty() && base.back() == '/') {
                    base.pop_back();
                }
                const auto url = base + "/api/client/updates/stream?" + query;
                std::string nonce;
                auto stream = impl_->pipeline.open_update_stream(url, nonce, stop);
                if (stream.status_code() < 200 || stream.status_code() >= 300) {
                    throw Error(ErrorKind::Api, stream.status_code(), {},
                        "update stream was rejected");
                }
                attempt = 0;
                SseReader reader(stream);
                bool verified = false;
                while (!stop.stop_requested()) {
                    const auto message = next_sse(reader, stop);
                    if (!message) {
                        throw Error(ErrorKind::Network, 0, {}, "update stream closed");
                    }
                    if (message->name.empty() || message->data.empty()) {
                        continue;
                    }
                    const auto payload = Bytes(message->data.begin(), message->data.end());
                    if (message->name == "authz") {
                        impl_->pipeline.verify_authz(internal::ProtocolResponse{
                            .status_code = 200, .body = payload, .request_nonce = nonce
                        });
                        verified = true;
                        continue;
                    }
                    if (message->name == "authz_expired") {
                        throw Error(ErrorKind::Session, 401, "authz_session_expired",
                            "update stream authorization expired");
                    }
                    if (!verified || message->name == "connected") {
                        continue;
                    }
                    const auto data = impl_->pipeline.verify_authz(internal::ProtocolResponse{
                        .status_code = 200, .body = payload, .request_nonce = nonce
                    });
                    auto event = event_from_json(data);
                    if (event.event_type.empty()) {
                        event.event_type = message->name;
                    }
                    if (event.id.empty()) {
                        event.id = message->id;
                    }
                    if (event.event_type == "device_shutdown" ||
                        event.event_type == "maintenance_scheduled" ||
                        event.event_type == "maintenance_cancelled") {
                        if (on_control) {
                            on_control(event);
                        }
                    }
                    if (on_event) {
                        on_event(event);
                    }
                }
                return;
            } catch (const Error& error) {
                if (on_error) {
                    on_error(error);
                }
                if (!options.reconnect || stop.stop_requested() ||
                    error.kind == ErrorKind::Session ||
                    error.kind == ErrorKind::Unauthorized ||
                    error.kind == ErrorKind::DeviceBlocked ||
                    error.kind == ErrorKind::Integrity) {
                    return;
                }
                auto delay = std::min(options.reconnect_max_backoff,
                    options.reconnect_backoff * static_cast<int>(1 << std::min<std::uint64_t>(attempt, 4)));
                if (options.jitter) {
                    const auto random = internal::random_bytes(2);
                    const auto value = static_cast<std::uint32_t>(
                        (random[0] << 8) | random[1]);
                    delay += std::chrono::milliseconds(
                        value % static_cast<std::uint32_t>(
                            std::max<int64_t>(1, delay.count() / 2)));
                }
                if (sleep_for_stream_backoff(delay, stop)) {
                    return;
                }
                ++attempt;
            } catch (const std::exception& exception) {
                const auto error = Error(ErrorKind::Protocol, 0, {},
                    std::string("update stream failed: ") + exception.what());
                if (on_error) {
                    on_error(error);
                }
                return;
            }
        }
    };
    return UpdateStream(std::make_unique<UpdateStream::Impl>(std::move(runner)));
}

Json Client::resolve_firmware_identity(const Json& metadata, const std::stop_token& stop) {
    if (!metadata.is_object()) {
        throw Error(ErrorKind::Configuration, 0, {},
            "firmware metadata must be a JSON object");
    }
    static constexpr std::string_view allowed_fields[] = {
        "ota_target_version", "version_name", "post_build", "oplus_rom_version",
        "android_version", "post_sdk_level"
    };
    Json normalized = Json::object();
    for (const auto& [key, value] : metadata.items()) {
        if (std::find(std::begin(allowed_fields), std::end(allowed_fields), key) ==
            std::end(allowed_fields)) {
            continue;
        }
        if (!value.is_string() || value.get_ref<const std::string&>().size() > 512) {
            throw Error(ErrorKind::Configuration, 0, {},
                "firmware metadata field is invalid: " + key);
        }
        normalized[key] = value;
    }
    if (normalized.empty()) {
        throw Error(ErrorKind::Configuration, 0, {},
            "firmware metadata must contain at least one supported field");
    }
    const auto response = impl_->pipeline.send_web("POST", "/api/v1/device-models/resolve",
        json_body(normalized), internal::OperationClass::FirmwareIdentity, true, nullptr, {}, {}, stop);
    impl_->pipeline.throw_if_error(response);
    return parse_body(response, "firmware identity response");
}

AsyncTask<Json> Client::resolve_firmware_identity_async(Json metadata) {
    return make_async([this, metadata = std::move(metadata)](const std::stop_token stop) {
        return resolve_firmware_identity(metadata, stop);
    });
}

DebugRequestTicket Client::create_debug_request(const std::string& note,
    const std::stop_token& stop) {
    if (note.size() < 2 || note.size() > 200) {
        throw Error(ErrorKind::Configuration, 0, {}, "debug note must contain 2 to 200 characters");
    }
    const auto enrollment = request_enrollment_ticket("debug", stop);
    const auto session_id = internal::base64url_encode(internal::random_bytes(32));
    Json enroll{
        {"ticket", enrollment.ticket},
        {"app_id", impl_->options.app_id},
        {"release_id", impl_->options.release_id},
        {"session_id", session_id},
        {"pcid", device_id()},
        {"app_version", impl_->options.version}
    };
    const auto enroll_response = impl_->pipeline.send_web("POST", "/api/v1/client/debug-enroll",
        json_body(enroll), internal::OperationClass::DebugProtocol, false, nullptr, {}, {}, stop);
    impl_->pipeline.throw_if_error(enroll_response);
    const auto credentials_body = parse_body(enroll_response, "debug enrollment response");
    const auto client_id = internal::json_get_string(credentials_body, "client_id");
    const auto client_secret = internal::json_get_string(credentials_body, "client_secret");
    const auto credentials_expires = internal::json_get_int64(credentials_body, "expires_at");
    const auto now = impl_->pipeline.clock().now_unix_seconds();
    if (client_id.empty() || client_secret.empty() ||
        credentials_expires <= now ||
        credentials_expires > now + 5 * 60 + 5) {
        throw Error(ErrorKind::Protocol, 0, {}, "debug enrollment response is invalid");
    }
    Json credentials{
        {"client_id", client_id},
        {"client_secret", client_secret},
        {"session_id", session_id}
    };
    Json create{
        {"session_id", session_id},
        {"pcid", device_id()},
        {"app_version", impl_->options.version},
        {"note", note}
    };
    const auto create_response = impl_->pipeline.send_web("POST", "/api/v1/client/debug-requests",
        json_body(create), internal::OperationClass::DebugProtocol, true, &credentials, {}, {}, stop);
    impl_->pipeline.throw_if_error(create_response);
    const auto created = parse_body(create_response, "debug create response");
    const auto request_id = internal::json_get_string(created, "request_id");
    const auto watch_token = internal::json_get_string(created, "watch_token");
    const auto expires_at = internal::json_get_int64(created, "expires_at");
    if (request_id.empty() || watch_token.empty() || expires_at <= now ||
        expires_at > now + 5 * 60 + 5) {
        throw Error(ErrorKind::Protocol, 0, {}, "debug create response is invalid");
    }
    {
        std::lock_guard lock(impl_->debug_mutex);
        impl_->debug_credentials[request_id] = credentials;
    }
    return DebugRequestTicket{request_id, watch_token, expires_at};
}

AsyncTask<DebugRequestTicket> Client::create_debug_request_async(std::string note) {
    return make_async([this, note = std::move(note)](const std::stop_token stop) {
        return create_debug_request(note, stop);
    });
}

void Client::cancel_debug_request(const DebugRequestTicket& ticket, const std::stop_token& stop) {
    Json credentials;
    {
        std::lock_guard lock(impl_->debug_mutex);
        const auto found = impl_->debug_credentials.find(ticket.request_id);
        if (found == impl_->debug_credentials.end()) {
            throw Error(ErrorKind::Configuration, 0, {},
                "debug request credentials are unavailable");
        }
        credentials = found->second;
    }
    const auto response = impl_->pipeline.send_web("POST",
        "/api/v1/client/debug-requests/" + ticket.request_id + "/cancel",
        {}, internal::OperationClass::DebugProtocol, true, &credentials,
        ticket.watch_token, {}, stop);
    impl_->pipeline.throw_if_error(response);
    std::lock_guard lock(impl_->debug_mutex);
    impl_->debug_credentials.erase(ticket.request_id);
}

AsyncTask<void> Client::cancel_debug_request_async(DebugRequestTicket ticket) {
    return make_async([this, ticket = std::move(ticket)](const std::stop_token stop) {
        cancel_debug_request(ticket, stop);
    });
}

UpdateStream Client::watch_debug_request(const DebugRequestTicket& ticket,
    std::function<void(const DebugDecisionEvent&)> on_decision,
    UpdateStream::ErrorCallback on_error) {
    Json credentials;
    {
        std::lock_guard lock(impl_->debug_mutex);
        const auto found = impl_->debug_credentials.find(ticket.request_id);
        if (found == impl_->debug_credentials.end()) {
            throw Error(ErrorKind::Configuration, 0, {},
                "debug request credentials are unavailable");
        }
        credentials = found->second;
    }
    auto runner = [this, ticket, credentials = std::move(credentials),
                      on_decision = std::move(on_decision),
                      on_error = std::move(on_error)](const std::stop_token stop) mutable {
        try {
            const auto path = "/api/v1/client/debug-requests/" + ticket.request_id + "/events";
            std::string nonce;
            auto stream = impl_->pipeline.open_web_stream(path, ticket.request_id,
                credentials, ticket.watch_token, nonce, stop);
            if (stream.status_code() < 200 || stream.status_code() >= 300) {
                throw Error(ErrorKind::Api, stream.status_code(), {},
                    "debug stream was rejected");
            }
            const auto session_id = internal::json_get_string(credentials, "session_id");
            const auto expected_hash = internal::sha256_hex(
                std::span(reinterpret_cast<const std::uint8_t*>(session_id.data()),
                    session_id.size()));
            SseReader reader(stream);
            while (!stop.stop_requested()) {
                const auto message = next_sse(reader, stop);
                if (!message) {
                    throw Error(ErrorKind::Network, 0, {}, "debug stream closed");
                }
                if (message->name == "authz_expired" || message->name == "authz-expired") {
                    throw Error(ErrorKind::Session, 401, "authz_session_expired",
                        "debug stream authorization expired");
                }
                if (message->name != "debug-request-state" &&
                    message->name != "debug_request_state") {
                    continue;
                }
                const Bytes payload(message->data.begin(), message->data.end());
                const auto data = impl_->pipeline.verify_authz(internal::ProtocolResponse{
                    .status_code = 200, .body = payload, .request_nonce = nonce
                });
                const auto version = internal::json_get_string(data, "version");
                const auto request_id = internal::json_get_string(data, "request_id");
                const auto session_hash = internal::json_get_string(data, "session_id_hash");
                const auto state = internal::json_get_string(data, "status");
                const auto reason = optional_string(data, "reason");
                const auto expires = internal::json_get_int64(data, "expires_at");
                if (version != "debug_decision_v1" || request_id != ticket.request_id ||
                    internal::lower_ascii(session_hash) != expected_hash ||
                    (state != "pending" && state != "approved" &&
                        state != "rejected" && state != "cancelled") ||
                    expires <= 0) {
                    throw Error(ErrorKind::Protocol, 0, {}, "debug decision payload is invalid");
                }
                if (on_decision) {
                    on_decision(DebugDecisionEvent{
                        .state = state,
                        .reason = reason,
                        .authorization_expires_at = state == "approved" ? expires : 0
                    });
                }
                if (state == "approved" || state == "rejected" || state == "cancelled") {
                    {
                        std::lock_guard lock(impl_->debug_mutex);
                        impl_->debug_credentials.erase(ticket.request_id);
                    }
                    return;
                }
            }
        } catch (const Error& error) {
            if (on_error) {
                on_error(error);
            }
        }
    };
    return UpdateStream(std::make_unique<UpdateStream::Impl>(std::move(runner)));
}

} // namespace swm
