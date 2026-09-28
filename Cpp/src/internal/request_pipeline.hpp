#pragma once

#include "internal/device_identity.hpp"
#include "internal/host_integrity.hpp"
#include "internal/http_client.hpp"
#include "internal/trusted_clock.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>

namespace swm::internal {

enum class OperationClass {
    TrustedTimeSync,
    OnlineKeyManifest,
    UpdateCheck,
    Heartbeat,
    OperationAuthorization,
    OperationGrantConsume,
    Events,
    Feedback,
    EnrollmentTicket,
    DeviceKeyRotation,
    Download,
    UpdateStream,
    FirmwareIdentity,
    DebugProtocol,
    DebugStream
};

struct RequestPolicy {
    int timeout_ms;
    int retries;
    int backoff_ms;
    int backoff_max_ms;
    int deadline_ms;
};

RequestPolicy resolve_request_policy(OperationClass operation);

struct ProtocolRequest {
    std::string method;
    std::string path;
    OperationClass operation = OperationClass::Events;
    Bytes body;
    bool encrypt_body = true;
    bool require_session = false;
    bool require_trusted_time = true;
    bool require_online_key = true;
    std::string content_type = "application/json; charset=utf-8";
    std::string query;
    std::string dpop_resource;
};

struct ProtocolResponse {
    int status_code = 0;
    Bytes body;
    std::string request_nonce;
    HttpHeaders headers;
};

class RequestPipeline final {
public:
    explicit RequestPipeline(ClientOptions options);
    ~RequestPipeline();

    RequestPipeline(const RequestPipeline&) = delete;
    RequestPipeline& operator=(const RequestPipeline&) = delete;

    [[nodiscard]] const std::string& device_id() const;
    [[nodiscard]] const std::string& install_id() const;
    [[nodiscard]] const std::string& device_key_id() const;
    [[nodiscard]] const TrustedClock& clock() const noexcept { return clock_; }
    [[nodiscard]] const std::optional<std::string>& session() const noexcept { return session_; }
    [[nodiscard]] bool host_integrity_required() const noexcept { return host_integrity_required_; }
    [[nodiscard]] const HostIntegrityManager& host_integrity() const noexcept { return host_integrity_; }

    void refresh_online_keys(bool force, const std::stop_token& stop);
    ProtocolResponse send(const ProtocolRequest& request, const std::stop_token& stop);
    Json send_and_verify(const ProtocolRequest& request, const std::stop_token& stop);
    void throw_if_error(const ProtocolResponse& response) const;

    Json create_device_auth(const std::string& challenge = {});
    DeviceKeyRotationResult rotate_device_key(const std::stop_token& stop);
    void set_host_integrity_required(bool required);
    Json verify_authz(const ProtocolResponse& response) const;
    std::string create_dpop(std::string_view method, std::string_view absolute_url,
        std::string_view session_binding, std::span<const std::uint8_t> body) const;
    ProtocolResponse send_web(const std::string& method, const std::string& path,
        const Bytes& body, OperationClass operation, bool include_dpop,
        const Json* debug_credentials, const std::string& watch_token,
        const std::string& request_id, const std::stop_token& stop);
    ResponseStream open_web_stream(const std::string& path,
        const std::string& request_id, const Json& debug_credentials,
        const std::string& watch_token, std::string& request_nonce,
        const std::stop_token& stop);
    ProtocolResponse send_download(const std::string& url, std::uint64_t range_start,
        const std::stop_token& stop);
    ProtocolResponse send_storage(const std::string& url, std::uint64_t range_start,
        const std::stop_token& stop);
    ResponseStream open_download_stream(const std::string& url, std::uint64_t range_start,
        bool authenticated, const std::stop_token& stop);
    ResponseStream open_update_stream(const std::string& url, std::string& request_nonce,
        const std::stop_token& stop);

    [[nodiscard]] bool offline_locked() const;
    void note_verified_interaction() const;
    void clear_session() noexcept;

private:
    struct ProtocolKey {
        std::string key_id;
        std::string public_key;
        std::int64_t issued_at = 0;
        std::int64_t refresh_after = 0;
    };

    ProtocolResponse send_attempt(const ProtocolRequest& request,
        const RequestPolicy& policy, const std::stop_token& stop);
    void refresh_trusted_time(const std::stop_token& stop);
    void refresh_online_keys_core(const std::stop_token& stop);
    void install_key(ProtocolKey key);
    [[nodiscard]] std::optional<ProtocolKey> find_key(std::string_view key_id) const;
    [[nodiscard]] ProtocolKey current_key() const;
    [[nodiscard]] bool has_fresh_key() const;
    [[nodiscard]] bool can_use_current_key_after_refresh_failure() const;
    [[nodiscard]] std::string ensure_session() const;
    [[nodiscard]] std::string ensure_trusted_now() const;
    [[nodiscard]] std::string absolute_url(std::string_view path,
        std::string_view query = {}) const;
    [[nodiscard]] std::string absolute_web_url(std::string_view path) const;
    [[nodiscard]] const DeviceIdentity& identity() const;
    [[nodiscard]] const HardwareEvidence& hardware() const;
    Json create_device_auth_for(const DeviceIdentity& identity,
        const std::string& challenge);

    ClientOptions options_;
    StateStore store_;
    TrustedClock clock_;
    HttpClient http_;
    HostIntegrityManager host_integrity_;
    mutable std::optional<DeviceIdentity> identity_;
    mutable std::optional<HardwareEvidence> hardware_;
    mutable std::optional<Bytes> offline_plain_;
    std::optional<ProtocolKey> current_key_;
    std::vector<ProtocolKey> previous_keys_;
    mutable std::optional<std::string> session_;
    mutable std::int64_t session_expires_at_ = 0;
    mutable bool offline_latched_ = false;
    bool host_integrity_required_ = false;
    mutable std::mutex mutex_;
    std::timed_mutex refresh_mutex_;
};

} // namespace swm::internal
