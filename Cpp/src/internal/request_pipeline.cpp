#include "internal/request_pipeline.hpp"
#include "internal/crypto.hpp"
#include "internal/hardware_evidence.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

namespace swm::internal {
namespace {

constexpr std::string_view header_app_id = "X-App-Id";
constexpr std::string_view header_timestamp = "X-Timestamp";
constexpr std::string_view header_nonce = "X-Nonce";
constexpr std::string_view header_capability = "X-Authz-Capability";
constexpr std::string_view header_release_id = "X-Client-Release-Id";
constexpr std::string_view header_version = "X-Client-Version";
constexpr std::string_view header_version_code = "X-Client-Version-Code";
constexpr std::string_view header_session = "X-SWM-Session";
constexpr std::string_view header_dpop = "X-SWM-DPoP";
constexpr std::string_view header_body_encryption = "X-SWM-Body-Enc";
constexpr std::string_view header_online_key = "X-SWM-Online-Key-Id";
constexpr std::string_view body_encryption = "x25519-aes-gcm-v1";
constexpr std::int64_t online_key_refresh_lead = 5 * 60;
constexpr std::size_t maximum_previous_keys = 4;
constexpr std::uint64_t maximum_offline_ms = 24ULL * 60 * 60 * 1000;

std::string query_string(const std::map<std::string, std::string, std::less<>>& query) {
    std::string output;
    for (const auto& [key, value] : query) {
        if (value.empty()) {
            continue;
        }
        if (!output.empty()) {
            output.push_back('&');
        }
        output += url_escape(key) + "=" + url_escape(value);
    }
    return output;
}

bool transient_status(const int status) {
    return status == 408 || status == 429 || status == 500 || status == 502 ||
        status == 503 || status == 504;
}

int retry_delay_ms(const RequestPolicy& policy, const int attempt) {
    if (policy.backoff_ms <= 0) {
        return 0;
    }
    const auto shift = std::min(attempt, 16);
    const auto scaled = static_cast<long long>(policy.backoff_ms) << shift;
    return static_cast<int>(std::min<long long>(scaled,
        std::max(policy.backoff_max_ms, policy.backoff_ms)));
}

bool can_wait(const RequestPolicy& policy, const std::uint64_t started,
    const int delay_ms, const int attempt) {
    if (attempt >= policy.retries) {
        return false;
    }
    if (policy.deadline_ms <= 0) {
        return true;
    }
    return TrustedClock::tick_ms() - started + delay_ms + policy.timeout_ms <=
        static_cast<std::uint64_t>(policy.deadline_ms);
}

struct ServiceError {
    std::string code;
    std::string message;
    std::string minimum_supported_version;
};

ServiceError json_service_error(const Json& body) {
    ServiceError result;
    const auto error = body.find("error");
    if (error == body.end()) {
        result.code = json_get_string(body, "code", false);
        result.message = json_get_string(body, "message", false);
        return result;
    }
    if (error->is_string()) {
        result.message = error->get<std::string>();
        if (!result.message.empty() && result.message.size() <= 128 &&
            std::all_of(result.message.begin(), result.message.end(), [](const char ch) {
                return std::islower(static_cast<unsigned char>(ch)) ||
                    std::isdigit(static_cast<unsigned char>(ch)) || ch == '_';
            })) {
            result.code = result.message;
        }
        return result;
    }
    if (!error->is_object()) {
        return result;
    }
    result.code = json_get_string(*error, "code", false);
    result.message = json_get_string(*error, "message", false);
    result.minimum_supported_version =
        json_get_string(*error, "minimum_supported_version", false);
    if (result.message.empty()) {
        result.message = result.code;
    }
    return result;
}

} // namespace

RequestPolicy resolve_request_policy(const OperationClass operation) {
    switch (operation) {
    case OperationClass::TrustedTimeSync: return {10000, 2, 1000, 4000, 40000};
    case OperationClass::OnlineKeyManifest: return {10000, 2, 1000, 4000, 40000};
    case OperationClass::UpdateCheck: return {15000, 2, 1500, 6000, 60000};
    case OperationClass::Heartbeat: return {8000, 2, 1000, 4000, 30000};
    case OperationClass::OperationAuthorization: return {10000, 2, 1000, 4000, 36000};
    case OperationClass::OperationGrantConsume: return {10000, 1, 1000, 2000, 24000};
    case OperationClass::Events: return {8000, 1, 1000, 2000, 20000};
    case OperationClass::Feedback: return {10000, 1, 1000, 2000, 24000};
    case OperationClass::EnrollmentTicket: return {10000, 1, 1000, 2000, 24000};
    case OperationClass::DeviceKeyRotation: return {10000, 1, 1000, 2000, 24000};
    case OperationClass::Download: return {30000, 2, 2000, 8000, 0};
    case OperationClass::UpdateStream: return {30000, 0, 0, 0, 0};
    case OperationClass::FirmwareIdentity: return {8000, 1, 500, 1000, 20000};
    case OperationClass::DebugProtocol: return {8000, 1, 500, 1000, 20000};
    case OperationClass::DebugStream: return {8000, 1, 500, 1000, 20000};
    }
    return {8000, 1, 1000, 2000, 20000};
}

RequestPipeline::RequestPipeline(ClientOptions options)
    : options_(std::move(options)),
      store_(options_.app_id, options_.storage_directory),
      http_(options_.allow_insecure_http),
      host_integrity_(options_, store_) {
    if (const auto cached = host_integrity_.read_cached_policy()) {
        host_integrity_required_ = *cached;
    }
}

RequestPipeline::~RequestPipeline() = default;

const std::string& RequestPipeline::device_id() const {
    if (!options_.device_id.empty()) {
        return options_.device_id;
    }
    return identity().device_id();
}

const std::string& RequestPipeline::install_id() const {
    return identity().install_id();
}

const std::string& RequestPipeline::device_key_id() const {
    return identity().key_id();
}

const DeviceIdentity& RequestPipeline::identity() const {
    if (!identity_) {
        identity_.emplace(DeviceIdentity::load_or_create(options_.app_id, store_));
    }
    return *identity_;
}

const HardwareEvidence& RequestPipeline::hardware() const {
    if (!hardware_) {
        hardware_ = collect_hardware_evidence(options_.app_id);
    }
    return *hardware_;
}

Json RequestPipeline::create_device_auth(const std::string& challenge) {
    return create_device_auth_for(identity(), challenge);
}

Json RequestPipeline::create_device_auth_for(const DeviceIdentity& identity_value,
    const std::string& challenge) {
    const auto& value = hardware();
    Json result{
        {"install_id", identity_value.install_id()},
        {"key_id", identity_value.key_id()},
        {"key_thumbprint", identity_value.key_thumbprint()},
        {"public_key_sec1", identity_value.public_key_sec1()},
        {"credential_version", "device_credential_v2"},
        {"hardware_evidence", {
            {"version", value.version},
            {"component_mask", value.component_mask},
            {"aggregate_hash", value.aggregate_hash}
        }}
    };
    if (!challenge.empty()) {
        result["challenge"] = challenge;
    }
    return result;
}

void RequestPipeline::set_host_integrity_required(const bool required) {
    host_integrity_required_ = required;
    host_integrity_.store_policy(required);
}

DeviceKeyRotationResult RequestPipeline::rotate_device_key(const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    refresh_online_keys(false, stop);
    static_cast<void>(ensure_session());
    auto pending = DeviceIdentity::create_pending(options_.app_id, store_);
    bool committed = false;
    try {
        std::string challenge;
        std::string proof_digest;
        for (int attempt = 0; attempt < 2; ++attempt) {
            Json payload{
                {"new_device_auth", create_device_auth_for(pending, challenge)}
            };
            if (!challenge.empty()) {
                const auto digest = hex_decode(proof_digest);
                if (digest.size() != 32) {
                    throw Error(ErrorKind::Protocol, 0,
                        {}, "device key rotation proof digest is invalid");
                }
                std::array<std::uint8_t, 32> value{};
                std::copy(digest.begin(), digest.end(), value.begin());
                payload["new_key_proof"] = base64url_encode(pending.sign_sha256(value));
            }
            const auto body = json_string(payload);
            const auto response = send(ProtocolRequest{
                .method = "POST",
                .path = "/api/client/device-key/rotate",
                .operation = OperationClass::DeviceKeyRotation,
                .body = Bytes(body.begin(), body.end()),
                .encrypt_body = true,
                .require_session = true,
                .require_trusted_time = true,
                .require_online_key = true
            }, stop);
            if (response.status_code == 428 && attempt == 0) {
                const auto challenge_body = parse_json(std::string_view(
                    reinterpret_cast<const char*>(response.body.data()), response.body.size()),
                    "device key rotation challenge");
                challenge = json_get_string(challenge_body, "challenge");
                proof_digest = json_get_string(challenge_body, "proof_digest");
                if (challenge.empty() || proof_digest.empty()) {
                    throw Error(ErrorKind::Protocol, 0,
                        {}, "device key rotation challenge is invalid");
                }
                continue;
            }
            throw_if_error(response);
            const auto parsed = parse_json(std::string_view(
                reinterpret_cast<const char*>(response.body.data()), response.body.size()),
                "device key rotation response");
            if (!json_get_bool(parsed, "rotated", false) ||
                json_get_string(parsed, "install_id", false) != pending.install_id() ||
                json_get_string(parsed, "key_id", false) != pending.key_id()) {
                throw Error(ErrorKind::Protocol, 0,
                    {}, "device key rotation response is invalid");
            }
            pending.commit_pending();
            committed = true;
            identity_ = std::move(pending);
            offline_plain_.reset();
            offline_latched_ = false;
            clear_session();
            return DeviceKeyRotationResult{
                .registration_id = json_get_string(parsed, "registration_id"),
                .install_id = identity_->install_id(),
                .key_id = identity_->key_id(),
                .device_id = device_id()
            };
        }
        throw Error(ErrorKind::Protocol, 0,
            {}, "device key rotation challenge retry was exhausted");
    } catch (...) {
        if (!committed) {
            pending.delete_pending();
        }
        throw;
    }
}

void RequestPipeline::clear_session() noexcept {
    session_.reset();
    session_expires_at_ = 0;
}

void RequestPipeline::refresh_online_keys(const bool force, const std::stop_token& stop) {
    if (!force && has_fresh_key()) {
        return;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(30000);
    while (!refresh_mutex_.try_lock_for(std::chrono::milliseconds(100))) {
        throw_if_stopped(stop);
        if (std::chrono::steady_clock::now() >= deadline) {
            throw Error(ErrorKind::Timeout, 0, {}, "online key refresh lock timeout");
        }
    }
    struct Unlock {
        std::timed_mutex* mutex;
        ~Unlock() { mutex->unlock(); }
    } unlock{&refresh_mutex_};
    if (!force && has_fresh_key()) {
        return;
    }
    try {
        if (!clock_.initialized()) {
            refresh_trusted_time(stop);
        }
        refresh_online_keys_core(stop);
    } catch (const Error& error) {
        if (!can_use_current_key_after_refresh_failure() ||
            (error.kind != ErrorKind::Network && error.kind != ErrorKind::Timeout &&
                error.status_code < 500)) {
            throw;
        }
    }
}

void RequestPipeline::refresh_trusted_time(const std::stop_token& stop) {
    const ProtocolRequest request{
        .method = "GET",
        .path = "/api/client/time",
        .operation = OperationClass::TrustedTimeSync,
        .encrypt_body = false,
        .require_session = false,
        .require_trusted_time = false,
        .require_online_key = false
    };
    const auto started = TrustedClock::tick_ms();
    const auto response = send(request, stop);
    const auto received = TrustedClock::tick_ms();
    throw_if_error(response);
    const auto body = parse_json(std::string_view(
        reinterpret_cast<const char*>(response.body.data()), response.body.size()),
        "signed server time");
    const auto version = json_get_string(body, "manifest_version");
    const auto app_id = json_get_string(body, "app_id");
    const auto release_id = json_get_string(body, "release_id");
    const auto nonce = json_get_string(body, "nonce");
    const auto root_key = json_get_string(body, "root_trust_key_id");
    const auto signature = json_get_string(body, "signature");
    const auto server_time = json_get_int64(body, "server_time_ms");
    const auto expires_at = json_get_int64(body, "expires_at_ms");
    if (version != "server_time_v1" || app_id != options_.app_id ||
        release_id != options_.release_id || nonce != response.request_nonce ||
        root_key != options_.root_trust_key_id || server_time <= 0 ||
        expires_at <= server_time || expires_at - server_time > 60000) {
        throw Error(ErrorKind::Clock, 0, {}, "signed server time identity or lifetime is invalid");
    }
    const auto canonical = std::string("server_time_v1\napp_id:") + app_id +
        "\nrelease_id:" + release_id + "\nnonce:" + nonce +
        "\nserver_time_ms:" + std::to_string(server_time) +
        "\nexpires_at_ms:" + std::to_string(expires_at) +
        "\nroot_trust_key_id:" + root_key;
    if (!ed25519_verify(options_.root_trust_public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size()),
            signature)) {
        throw Error(ErrorKind::Clock, 0, {}, "signed server time signature is invalid");
    }
    clock_.set_authoritative_time(server_time, started, received);
    note_verified_interaction();
}

void RequestPipeline::refresh_online_keys_core(const std::stop_token& stop) {
    const ProtocolRequest request{
        .method = "GET",
        .path = "/api/client/key-manifest",
        .operation = OperationClass::OnlineKeyManifest,
        .encrypt_body = false,
        .require_session = false,
        .require_trusted_time = true,
        .require_online_key = false
    };
    const auto response = send(request, stop);
    throw_if_error(response);
    const auto manifest = parse_json(std::string_view(
        reinterpret_cast<const char*>(response.body.data()), response.body.size()),
        "online key manifest");
    const auto version = json_get_string(manifest, "manifest_version");
    const auto purpose = json_get_string(manifest, "purpose");
    const auto app_id = json_get_string(manifest, "app_id");
    const auto release_id = json_get_string(manifest, "release_id");
    const auto key_id = json_get_string(manifest, "key_id");
    const auto public_key = json_get_string(manifest, "public_key");
    const auto root_id = json_get_string(manifest, "root_trust_key_id");
    const auto signature = json_get_string(manifest, "root_trust_signature");
    const auto issued_at = json_get_int64(manifest, "issued_at");
    const auto refresh_after = json_get_int64(manifest, "refresh_after");
    const auto now = clock_.now_unix_seconds();
    if (version != "online_key_manifest_v1" || purpose != "online_body" ||
        app_id != options_.app_id || release_id != options_.release_id ||
        root_id != options_.root_trust_key_id || key_id.empty() || public_key.empty() ||
        issued_at <= 0 || refresh_after <= issued_at ||
        refresh_after - issued_at > 30LL * 24 * 60 * 60 ||
        issued_at > now + 120 || refresh_after < now - 120) {
        throw Error(ErrorKind::Integrity, 0, "online_key_manifest_invalid",
            "online key manifest identity or lifetime is invalid");
    }
    const auto canonical = std::string("online_key_manifest_v1\npurpose:") + purpose +
        "\napp_id:" + app_id + "\nrelease_id:" + release_id + "\nkey_id:" + key_id +
        "\npublic_key:" + public_key + "\nroot_trust_key_id:" + root_id +
        "\nissued_at:" + std::to_string(issued_at) +
        "\nrefresh_after:" + std::to_string(refresh_after);
    if (!ed25519_verify(options_.root_trust_public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size()),
            signature)) {
        throw Error(ErrorKind::Integrity, 0, "online_key_manifest_invalid",
            "online key manifest root signature is invalid");
    }
    install_key({key_id, public_key, issued_at, refresh_after});
}

bool RequestPipeline::has_fresh_key() const {
    std::lock_guard lock(mutex_);
    return current_key_.has_value() && clock_.initialized() &&
        clock_.now_unix_seconds() < current_key_->refresh_after - online_key_refresh_lead;
}

bool RequestPipeline::can_use_current_key_after_refresh_failure() const {
    std::lock_guard lock(mutex_);
    return current_key_.has_value() && clock_.initialized() &&
        clock_.now_unix_seconds() < current_key_->refresh_after;
}

RequestPipeline::ProtocolKey RequestPipeline::current_key() const {
    std::lock_guard lock(mutex_);
    if (!current_key_) {
        throw Error(ErrorKind::Session, 401, "authz_key_required",
            "online authorization key is unavailable");
    }
    if (clock_.initialized() && clock_.now_unix_seconds() >= current_key_->refresh_after) {
        throw Error(ErrorKind::Session, 401, "authz_key_expired",
            "online authorization key has expired");
    }
    return *current_key_;
}

std::optional<RequestPipeline::ProtocolKey> RequestPipeline::find_key(
    const std::string_view key_id) const {
    std::lock_guard lock(mutex_);
    if (current_key_ && current_key_->key_id == key_id) {
        return *current_key_;
    }
    const auto found = std::find_if(previous_keys_.rbegin(), previous_keys_.rend(),
        [&](const ProtocolKey& key) { return key.key_id == key_id; });
    return found == previous_keys_.rend()
        ? std::nullopt : std::optional<ProtocolKey>(*found);
}

void RequestPipeline::install_key(ProtocolKey key) {
    std::lock_guard lock(mutex_);
    if (current_key_ && current_key_->key_id == key.key_id) {
        if (current_key_->public_key != key.public_key) {
            throw Error(ErrorKind::Integrity, 0, "online_key_manifest_invalid",
                "online key id was rebound to different key material");
        }
        *current_key_ = std::move(key);
        return;
    }
    const auto old = std::find_if(previous_keys_.begin(), previous_keys_.end(),
        [&](const ProtocolKey& item) { return item.key_id == key.key_id; });
    if (old != previous_keys_.end()) {
        if (old->public_key != key.public_key) {
            throw Error(ErrorKind::Integrity, 0, "online_key_manifest_invalid",
                "online key id was rebound to different key material");
        }
        previous_keys_.erase(old);
    }
    if (current_key_) {
        previous_keys_.push_back(*current_key_);
        while (previous_keys_.size() > maximum_previous_keys) {
            previous_keys_.erase(previous_keys_.begin());
        }
    }
    current_key_ = std::move(key);
}

std::string RequestPipeline::ensure_session() const {
    if (!clock_.initialized()) {
        throw Error(ErrorKind::Clock, 0, {},
            "trusted server time is unavailable for session validation");
    }
    const auto now = clock_.now_unix_seconds();
    if (!session_ || session_expires_at_ <= now) {
        throw Error(ErrorKind::Session, 401, "authz_session_invalid",
            "authorization session is missing or expired");
    }
    return *session_;
}

std::string RequestPipeline::ensure_trusted_now() const {
    const auto now = clock_.now_unix_seconds();
    if (now <= 0) {
        throw Error(ErrorKind::Clock, 0, {}, "trusted server time is unavailable");
    }
    return std::to_string(now);
}

std::string RequestPipeline::absolute_url(const std::string_view path,
    const std::string_view query) const {
    auto base = options_.base_url;
    while (!base.empty() && base.back() == '/') {
        base.pop_back();
    }
    return base + std::string(path) + (query.empty() ? std::string{} : "?" + std::string(query));
}

std::string RequestPipeline::absolute_web_url(const std::string_view path) const {
    auto base = options_.web_base_url.empty() ? options_.base_url : options_.web_base_url;
    while (!base.empty() && base.back() == '/') {
        base.pop_back();
    }
    return base + std::string(path);
}

ProtocolResponse RequestPipeline::send(const ProtocolRequest& request,
    const std::stop_token& stop) {
    if (request.require_trusted_time && !clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    if (request.require_online_key) {
        refresh_online_keys(false, stop);
    }
    if (request.require_session) {
        static_cast<void>(ensure_session());
    }
    const auto policy = resolve_request_policy(request.operation);
    const auto started = TrustedClock::tick_ms();
    std::optional<Error> last_error;
    for (int attempt = 0; attempt <= policy.retries; ++attempt) {
        throw_if_stopped(stop);
        if (policy.deadline_ms > 0 &&
            TrustedClock::tick_ms() - started + policy.timeout_ms >
                static_cast<std::uint64_t>(policy.deadline_ms)) {
            break;
        }
        try {
            auto response = send_attempt(request, policy, stop);
            if (transient_status(response.status_code) && attempt < policy.retries) {
                const auto delay = std::max(retry_delay_ms(policy, attempt), 0);
                if (!can_wait(policy, started, delay, attempt)) {
                    return response;
                }
                if (delay > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                }
                continue;
            }
            return response;
        } catch (const Error& error) {
            if (error.kind != ErrorKind::Network && error.kind != ErrorKind::Timeout) {
                throw;
            }
            last_error = error;
            if (attempt >= policy.retries) {
                break;
            }
            const auto delay = retry_delay_ms(policy, attempt);
            if (!can_wait(policy, started, delay, attempt)) {
                break;
            }
            if (delay > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }
        }
    }
    if (last_error) {
        throw *last_error;
    }
    throw Error(ErrorKind::Timeout, 0, {}, "request deadline exceeded");
}

ProtocolResponse RequestPipeline::send_attempt(const ProtocolRequest& request,
    const RequestPolicy& policy, const std::stop_token& stop) {
    throw_if_stopped(stop);
    const auto timestamp = request.require_trusted_time ? ensure_trusted_now() :
        std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    const auto nonce = random_uuid();
    const auto url = request.dpop_resource.empty() ?
        absolute_url(request.path, request.query) : request.dpop_resource;
    HttpRequest http_request;
    http_request.method = request.method;
    http_request.url = absolute_url(request.path, request.query);
    http_request.timeout_ms = policy.timeout_ms;
    http_request.maximum_response_bytes = 16 * 1024 * 1024;
    http_request.headers.add(std::string(header_app_id), options_.app_id);
    http_request.headers.add(std::string(header_timestamp), timestamp);
    http_request.headers.add(std::string(header_nonce), nonce);
    http_request.headers.add(std::string(header_capability), "v3");
    http_request.headers.add(std::string(header_release_id), options_.release_id);
    http_request.headers.add(std::string(header_version), options_.version);
    http_request.headers.add(std::string(header_version_code),
        options_.version_code.has_value() ? std::to_string(*options_.version_code) : std::string{});

    if (request.require_online_key) {
        const auto key = current_key();
        const auto session_binding = request.require_session ? ensure_session() : std::string{};
        http_request.headers.add(std::string(header_dpop),
            create_dpop(request.method, url, session_binding, request.body));
        if (request.require_session) {
            http_request.headers.add(std::string(header_session), session_binding);
        }
        if (request.encrypt_body) {
            http_request.body = encrypt_request_body(request.method, request.path,
                canonical_query(request.query), std::stoll(timestamp), nonce, options_.app_id,
                options_.release_id, options_.version,
                options_.version_code.has_value() ? std::to_string(*options_.version_code) : std::string{},
                key.key_id, key.public_key, request.body);
            http_request.headers.add(std::string(header_body_encryption),
                std::string(body_encryption));
            http_request.headers.add(std::string(header_online_key), key.key_id);
        } else {
            http_request.body = request.body;
        }
    } else {
        http_request.body = request.body;
    }
    if (!request.content_type.empty()) {
        http_request.headers.add("content-type", request.content_type);
    }
    const auto response = http_.request(http_request, stop);
    return ProtocolResponse{
        .status_code = response.status_code,
        .body = response.body,
        .request_nonce = nonce,
        .headers = response.headers
    };
}

Json RequestPipeline::verify_authz(const ProtocolResponse& response) const {
    throw_if_error(response);
    const auto carrier = parse_json(std::string_view(
        reinterpret_cast<const char*>(response.body.data()), response.body.size()),
        "Authz v3 carrier");
    if (!carrier.contains("data") || !carrier.contains("authz") || !carrier["authz"].is_object()) {
        throw Error(ErrorKind::Protocol, 0, {}, "Authz v3 carrier is incomplete");
    }
    const auto& authz = carrier["authz"];
    const auto raw_data = extract_json_member_raw(std::string_view(
        reinterpret_cast<const char*>(response.body.data()), response.body.size()), "data");
    if (!raw_data) {
        throw Error(ErrorKind::Protocol, 0, {}, "Authz v3 response data is missing");
    }
    const auto version = json_get_string(authz, "version");
    const auto decision = json_get_string(authz, "decision");
    const auto release = json_get_string(authz, "release_id");
    const auto device = json_get_string(authz, "device_id");
    const auto nonce = json_get_string(authz, "nonce");
    const auto data_hash = json_get_string(authz, "data_sha256");
    const auto key_id = json_get_string(authz, "key_id");
    const auto reason = json_get_string(authz, "reason", false);
    const auto session = json_get_string(authz, "session", false);
    const auto signature = json_get_string(authz, "signature");
    const auto issued_at = json_get_int64(authz, "issued_at");
    const auto expires_at = json_get_int64(authz, "expires_at");
    const auto now = clock_.now_unix_seconds();
    if (version != "authz_v3" || decision != "allow" || release != options_.release_id ||
        device != device_id() || nonce != response.request_nonce || issued_at <= 0 ||
        expires_at <= issued_at || expires_at - issued_at > 900 ||
        issued_at > now + 120 || expires_at < now - 120) {
        throw Error(ErrorKind::Unauthorized, 403, "authz_invalid",
            "Authz v3 response identity or lifetime is invalid");
    }
    const auto digest = sha256_hex(*raw_data);
    if (lower_ascii(digest) != lower_ascii(data_hash)) {
        throw Error(ErrorKind::Integrity, 403, "authz_data_mismatch",
            "Authz v3 response data hash is invalid");
    }
    const auto key = find_key(key_id);
    if (!key) {
        throw Error(ErrorKind::Unauthorized, 403, "authz_invalid",
            "Authz v3 response key is unknown");
    }
    const auto canonical = std::string("authz_v3\napp_id:") + options_.app_id +
        "\nrelease_id:" + release + "\ndevice_id:" + device + "\nnonce:" + nonce +
        "\ndecision:" + decision + "\nreason:" + reason + "\ndata_sha256:" + data_hash +
        "\nsession:" + session + "\nissued_at:" + std::to_string(issued_at) +
        "\nexpires_at:" + std::to_string(expires_at) + "\nkey_id:" + key_id;
    if (!ed25519_verify(key->public_key,
            std::span(reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size()),
            signature)) {
        throw Error(ErrorKind::Integrity, 403, "authz_signature_invalid",
            "Authz v3 response signature is invalid");
    }
    if (!session.empty()) {
        session_ = session;
        session_expires_at_ = expires_at;
    }
    note_verified_interaction();
    return carrier["data"];
}

Json RequestPipeline::send_and_verify(const ProtocolRequest& request,
    const std::stop_token& stop) {
    return verify_authz(send(request, stop));
}

void RequestPipeline::throw_if_error(const ProtocolResponse& response) const {
    if (response.status_code >= 200 && response.status_code < 300) {
        return;
    }
    std::string message;
    std::string code;
    std::string minimum_supported_version;
    IntegrityFailureAction action = IntegrityFailureAction::ShutdownClient;
    try {
        const auto body = parse_json(std::string_view(
            reinterpret_cast<const char*>(response.body.data()), response.body.size()),
            "service error");
        const auto parsed = json_service_error(body);
        code = parsed.code;
        message = parsed.message;
        minimum_supported_version = parsed.minimum_supported_version;
        if (body.contains("error") && body["error"].is_object() &&
            body["error"].contains("failure_action") && body["error"]["failure_action"].is_string()) {
            action = body["error"]["failure_action"].get<std::string>() == "deny_operations"
                ? IntegrityFailureAction::DenyOperations : IntegrityFailureAction::ShutdownClient;
        }
    } catch (...) {
        message.assign(reinterpret_cast<const char*>(response.body.data()), response.body.size());
    }
    if (code == "device_blocked") {
        throw Error(ErrorKind::DeviceBlocked, response.status_code, code, message);
    }
    if (code == "client_version_unsupported") {
        throw Error(ErrorKind::UnsupportedVersion, response.status_code, code, message,
            {}, IntegrityFailureAction::ShutdownClient, minimum_supported_version);
    }
    if (code == "update_region_blocked") {
        throw Error(ErrorKind::UpdateRegionBlocked, response.status_code, code, message);
    }
    if (code == "feedback_disabled") {
        throw Error(ErrorKind::FeedbackDisabled, response.status_code, code, message);
    }
    if (code.rfind("release_integrity_", 0) == 0) {
        throw Error(ErrorKind::Integrity, response.status_code, code, message,
            std::string(reinterpret_cast<const char*>(response.body.data()), response.body.size()), action);
    }
    if (code.rfind("operation_auth_", 0) == 0 || code.rfind("operation_grant_", 0) == 0) {
        throw Error(ErrorKind::OperationAuthorization, response.status_code, code, message);
    }
    if (response.status_code == 401) {
        throw Error(ErrorKind::Session, response.status_code, code, message);
    }
    if (response.status_code == 403) {
        throw Error(ErrorKind::Unauthorized, response.status_code, code, message);
    }
    if (response.status_code == 429) {
        throw Error(ErrorKind::RateLimit, response.status_code, code, message);
    }
    throw Error(response.status_code >= 500 ? ErrorKind::Api : ErrorKind::Validation,
        response.status_code, code, message);
}

std::string RequestPipeline::create_dpop(const std::string_view method,
    const std::string_view absolute_url_value, const std::string_view session_binding,
    const std::span<const std::uint8_t> body) const {
    const auto now = clock_.now_unix_seconds();
    if (now <= 0) {
        throw Error(ErrorKind::Clock, 0, {}, "trusted server time is unavailable");
    }
    Json header{
        {"alg", "ES256"},
        {"kid", device_key_id()},
        {"typ", "swm-dpop+jwt"}
    };
    const auto body_hash = sha256_hex(body);
    const auto session_hash = base64url_encode(sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(session_binding.data()), session_binding.size())));
    Json payload{
        {"app_id", options_.app_id},
        {"ath", session_hash},
        {"body_sha256", body_hash},
        {"channel", options_.channel},
        {"device_id", device_id()},
        {"exp", now + 60},
        {"htm", method},
        {"htu", absolute_url_value},
        {"iat", now},
        {"install_id", install_id()},
        {"jti", hex_lower(random_bytes(16))},
        {"pcid", device_id()},
        {"release_id", options_.release_id}
    };
    const auto encoded_header = base64url_encode(std::span(
        reinterpret_cast<const std::uint8_t*>(header.dump().data()), header.dump().size()));
    const auto payload_text = payload.dump();
    const auto encoded_payload = base64url_encode(std::span(
        reinterpret_cast<const std::uint8_t*>(payload_text.data()), payload_text.size()));
    const auto signing_input = encoded_header + "." + encoded_payload;
    const auto digest = sha256(std::span(
        reinterpret_cast<const std::uint8_t*>(signing_input.data()), signing_input.size()));
    const auto signature = identity().sign_sha256(digest);
    return signing_input + "." + base64url_encode(signature);
}

bool RequestPipeline::offline_locked() const {
    std::lock_guard lock(mutex_);
    if (offline_latched_) {
        return true;
    }
    const auto plaintext = store_.read_protected("offline.bin");
    if (!plaintext) {
        return true;
    }
    const std::string text(plaintext->begin(), plaintext->end());
    std::istringstream stream(text);
    std::string header;
    std::string install;
    std::string thumbprint;
    std::string milliseconds;
    if (!std::getline(stream, header) || !std::getline(stream, install) ||
        !std::getline(stream, thumbprint) || !std::getline(stream, milliseconds) ||
        header != "SwmSdkOfflineBudgetV1" || install != install_id() ||
        thumbprint != identity().key_thumbprint()) {
        return true;
    }
    std::int64_t last = 0;
    try {
        last = std::stoll(milliseconds);
    } catch (...) {
        return true;
    }
    if (last <= 0) {
        return true;
    }
    const auto now = clock_.now_unix_ms();
    return now <= 0 || now < last || static_cast<std::uint64_t>(now - last) > maximum_offline_ms;
}

void RequestPipeline::note_verified_interaction() const {
    std::lock_guard lock(mutex_);
    const auto now = clock_.now_unix_ms();
    if (now <= 0) {
        return;
    }
    auto last = 0LL;
    if (const auto plaintext = store_.read_protected("offline.bin")) {
        const std::string text(plaintext->begin(), plaintext->end());
        std::istringstream stream(text);
        std::string header;
        std::string install;
        std::string thumbprint;
        std::string milliseconds;
        if (std::getline(stream, header) && std::getline(stream, install) &&
            std::getline(stream, thumbprint) && std::getline(stream, milliseconds) &&
            header == "SwmSdkOfflineBudgetV1" && install == install_id() &&
            thumbprint == identity().key_thumbprint()) {
            try {
                last = std::stoll(milliseconds);
            } catch (...) {
                last = 0;
            }
        }
    }
    if (last > 0 && now >= last && static_cast<std::uint64_t>(now - last) > maximum_offline_ms) {
        offline_latched_ = true;
    }
    const auto text = "SwmSdkOfflineBudgetV1\n" + install_id() + "\n" +
        identity().key_thumbprint() + "\n" + std::to_string(now) + "\n";
    store_.write_protected("offline.bin", std::span(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

ProtocolResponse RequestPipeline::send_web(const std::string& method, const std::string& path,
    const Bytes& body, const OperationClass operation, const bool include_dpop,
    const Json* debug_credentials, const std::string& watch_token,
    const std::string& request_id, const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    const auto policy = resolve_request_policy(operation);
    const auto url = absolute_web_url(path);
    const auto session = (include_dpop || debug_credentials != nullptr)
        ? ensure_session() : std::string{};
    const auto started = TrustedClock::tick_ms();
    std::optional<Error> last_error;
    for (int attempt = 0; attempt <= policy.retries; ++attempt) {
        throw_if_stopped(stop);
        if (policy.deadline_ms > 0 &&
            TrustedClock::tick_ms() - started + policy.timeout_ms >
                static_cast<std::uint64_t>(policy.deadline_ms)) {
            break;
        }
        try {
            HttpRequest request;
            request.method = method;
            request.url = url;
            request.timeout_ms = policy.timeout_ms;
            request.body = body;
            request.headers.add("accept", "application/json");
            if (!body.empty()) {
                request.headers.add("content-type", "application/json; charset=utf-8");
            }
            if (include_dpop) {
                request.headers.add(std::string(header_session), session);
                request.headers.add(std::string(header_dpop),
                    create_dpop(method, url, session, body));
            }
            if (debug_credentials != nullptr) {
                const auto timestamp = ensure_trusted_now();
                const auto nonce = hex_lower(random_bytes(16));
                const auto client_id = json_get_string(*debug_credentials, "client_id");
                const auto secret = json_get_string(*debug_credentials, "client_secret");
                const auto canonical = std::string(method) + "\n" + path + "\n\n" +
                    sha256_hex(body) + "\n" + timestamp + "\n" + nonce + "\n" + client_id;
                request.headers.add("x-client-id", client_id);
                request.headers.add("x-timestamp", timestamp);
                request.headers.add("x-nonce", nonce);
                request.headers.add("x-signature-version", "1");
                request.headers.add("x-signature", hmac_sha256_hex(secret, canonical));
            }
            if (!watch_token.empty()) {
                request.headers.add("x-debug-watch-token", watch_token);
            }
            if (!request_id.empty()) {
                request.headers.add("x-debug-request-id", request_id);
            }
            const auto response = http_.request(request, stop);
            if (!transient_status(response.status_code) || attempt >= policy.retries) {
                return ProtocolResponse{
                    .status_code = response.status_code,
                    .body = response.body,
                    .request_nonce = random_uuid(),
                    .headers = response.headers
                };
            }
            const auto delay = retry_delay_ms(policy, attempt);
            if (!can_wait(policy, started, delay, attempt)) {
                return ProtocolResponse{
                    .status_code = response.status_code,
                    .body = response.body,
                    .request_nonce = random_uuid(),
                    .headers = response.headers
                };
            }
            if (delay > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }
        } catch (const Error& error) {
            if (error.kind != ErrorKind::Network && error.kind != ErrorKind::Timeout) {
                throw;
            }
            last_error = error;
            if (attempt >= policy.retries) {
                break;
            }
            const auto delay = retry_delay_ms(policy, attempt);
            if (!can_wait(policy, started, delay, attempt)) {
                break;
            }
            if (delay > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }
        }
    }
    if (last_error) {
        throw *last_error;
    }
    throw Error(ErrorKind::Timeout, 0, {}, "web request deadline exceeded");
}

ResponseStream RequestPipeline::open_web_stream(const std::string& path,
    const std::string& request_id, const Json& debug_credentials,
    const std::string& watch_token, std::string& request_nonce,
    const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    const auto url = absolute_web_url(path);
    const auto session = ensure_session();
    request_nonce = hex_lower(random_bytes(16));
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.timeout_ms = resolve_request_policy(OperationClass::DebugStream).timeout_ms;
    request.headers.add("accept", "text/event-stream");
    request.headers.add(std::string(header_session), session);
    request.headers.add(std::string(header_dpop),
        create_dpop("GET", url, session, {}));
    const auto client_id = json_get_string(debug_credentials, "client_id");
    const auto secret = json_get_string(debug_credentials, "client_secret");
    const auto timestamp = ensure_trusted_now();
    const auto canonical = "GET\n" + path + "\n\n" + sha256_hex({}) + "\n" +
        timestamp + "\n" + request_nonce + "\n" + client_id;
    request.headers.add("x-client-id", client_id);
    request.headers.add("x-timestamp", timestamp);
    request.headers.add("x-nonce", request_nonce);
    request.headers.add("x-signature-version", "1");
    request.headers.add("x-signature", hmac_sha256_hex(secret, canonical));
    request.headers.add("x-debug-watch-token", watch_token);
    if (!request_id.empty()) {
        request.headers.add("x-debug-request-id", request_id);
    }
    return http_.stream(request, stop);
}

ProtocolResponse RequestPipeline::send_download(const std::string& url,
    const std::uint64_t range_start, const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.timeout_ms = resolve_request_policy(OperationClass::Download).timeout_ms;
    request.maximum_response_bytes = 64 * 1024;
    if (range_start > 0) {
        request.headers.add("range", "bytes=" + std::to_string(range_start) + "-");
    }
    const auto session = ensure_session();
    request.headers.add(std::string(header_session), session);
    request.headers.add(std::string(header_dpop),
        create_dpop("GET", url, session, {}));
    const auto response = http_.request(request, stop);
    return ProtocolResponse{
        .status_code = response.status_code,
        .body = response.body,
        .request_nonce = random_uuid(),
        .headers = response.headers
    };
}

ProtocolResponse RequestPipeline::send_storage(const std::string& url,
    const std::uint64_t range_start, const std::stop_token& stop) {
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.timeout_ms = resolve_request_policy(OperationClass::Download).timeout_ms;
    request.maximum_response_bytes = 64 * 1024;
    if (range_start > 0) {
        request.headers.add("range", "bytes=" + std::to_string(range_start) + "-");
    }
    const auto response = http_.request(request, stop);
    return ProtocolResponse{
        .status_code = response.status_code,
        .body = response.body,
        .request_nonce = random_uuid(),
        .headers = response.headers
    };
}

ResponseStream RequestPipeline::open_download_stream(const std::string& url,
    const std::uint64_t range_start, const bool authenticated,
    const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.timeout_ms = resolve_request_policy(OperationClass::Download).timeout_ms;
    if (range_start > 0) {
        request.headers.add("range", "bytes=" + std::to_string(range_start) + "-");
    }
    if (authenticated) {
        const auto session = ensure_session();
        request.headers.add(std::string(header_session), session);
        request.headers.add(std::string(header_dpop),
            create_dpop("GET", url, session, {}));
    }
    return http_.stream(request, stop);
}

ResponseStream RequestPipeline::open_update_stream(const std::string& url,
    std::string& request_nonce, const std::stop_token& stop) {
    if (!clock_.initialized()) {
        refresh_trusted_time(stop);
    }
    const auto session = ensure_session();
    request_nonce = random_uuid();
    HttpRequest request;
    request.method = "GET";
    request.url = url;
    request.timeout_ms = resolve_request_policy(OperationClass::UpdateStream).timeout_ms;
    request.headers.add("accept", "text/event-stream");
    request.headers.add(std::string(header_app_id), options_.app_id);
    request.headers.add(std::string(header_timestamp), ensure_trusted_now());
    request.headers.add(std::string(header_nonce), request_nonce);
    request.headers.add(std::string(header_capability), "v3");
    request.headers.add(std::string(header_release_id), options_.release_id);
    request.headers.add(std::string(header_version), options_.version);
    request.headers.add(std::string(header_version_code),
        options_.version_code.has_value() ? std::to_string(*options_.version_code) : std::string{});
    request.headers.add(std::string(header_session), session);
    request.headers.add(std::string(header_dpop),
        create_dpop("GET", url, session, {}));
    return http_.stream(request, stop);
}

} // namespace swm::internal
