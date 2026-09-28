#pragma once

#include "swm/async_task.hpp"
#include "swm/types.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <stop_token>

namespace swm {

class UpdateStream final {
public:
    using EventCallback = std::function<void(const UpdateEvent&)>;
    using ErrorCallback = std::function<void(const Error&)>;
    using ControlCallback = std::function<void(const UpdateEvent&)>;

    UpdateStream();
    UpdateStream(const UpdateStream&) = delete;
    UpdateStream& operator=(const UpdateStream&) = delete;
    UpdateStream(UpdateStream&&) noexcept;
    UpdateStream& operator=(UpdateStream&&) noexcept;
    ~UpdateStream();

    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept;

private:
    struct Impl;
    explicit UpdateStream(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
    friend class Client;
};

class Client final {
public:
    explicit Client(ClientOptions options);
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;
    ~Client();

    [[nodiscard]] const std::string& device_id() const noexcept;
    [[nodiscard]] const std::string& install_id() const noexcept;
    [[nodiscard]] const std::string& device_key_id() const noexcept;

    void refresh_online_keys(const std::stop_token& stop = {});
    AsyncTask<void> refresh_online_keys_async();

    UpdateInfo check_update(const Json& attributes = Json::object(),
        const std::string& user_id = {}, const std::stop_token& stop = {});
    AsyncTask<UpdateInfo> check_update_async(Json attributes = Json::object(), std::string user_id = {});

    HeartbeatResult report_heartbeat(const std::string& app_version = {},
        const Json& attributes = Json::object(), const std::string& user_id = {},
        const std::stop_token& stop = {});
    AsyncTask<HeartbeatResult> report_heartbeat_async(std::string app_version = {},
        Json attributes = Json::object(), std::string user_id = {});

    void report_event(const Event& event, const std::stop_token& stop = {});
    void report_events(const std::vector<Event>& events, const std::stop_token& stop = {});
    AsyncTask<void> report_event_async(Event event);
    AsyncTask<void> report_events_async(std::vector<Event> events);

    FeedbackResult submit_feedback(const FeedbackRequest& request,
        const std::stop_token& stop = {});
    AsyncTask<FeedbackResult> submit_feedback_async(FeedbackRequest request);

    EnrollmentTicket request_enrollment_ticket(const std::string& audience,
        const std::stop_token& stop = {});
    AsyncTask<EnrollmentTicket> request_enrollment_ticket_async(std::string audience);

    DeviceKeyRotationResult rotate_device_key(const std::stop_token& stop = {});
    AsyncTask<DeviceKeyRotationResult> rotate_device_key_async();

    OperationGrant authorize_operation(const OperationAuthorizationRequest& request,
        const std::stop_token& stop = {});
    AsyncTask<OperationGrant> authorize_operation_async(OperationAuthorizationRequest request);

    OperationConsumptionReceipt consume_operation_authorization(const OperationGrant& grant,
        const std::stop_token& stop = {});
    AsyncTask<OperationConsumptionReceipt> consume_operation_authorization_async(OperationGrant grant);

    void download_update(const UpdateInfo& update, const std::filesystem::path& destination,
        const std::function<void(std::uint64_t, std::uint64_t)>& progress = {},
        const std::stop_token& stop = {});
    AsyncTask<void> download_update_async(UpdateInfo update, std::filesystem::path destination,
        std::function<void(std::uint64_t, std::uint64_t)> progress = {});

    UpdateStream watch_updates(UpdateStreamOptions options,
        UpdateStream::EventCallback on_event, UpdateStream::ErrorCallback on_error = {},
        UpdateStream::ControlCallback on_control = {});

    Json resolve_firmware_identity(const Json& metadata, const std::stop_token& stop = {});
    AsyncTask<Json> resolve_firmware_identity_async(Json metadata);

    DebugRequestTicket create_debug_request(const std::string& note,
        const std::stop_token& stop = {});
    AsyncTask<DebugRequestTicket> create_debug_request_async(std::string note);

    void cancel_debug_request(const DebugRequestTicket& ticket, const std::stop_token& stop = {});
    AsyncTask<void> cancel_debug_request_async(DebugRequestTicket ticket);

    UpdateStream watch_debug_request(const DebugRequestTicket& ticket,
        std::function<void(const DebugDecisionEvent&)> on_decision,
        UpdateStream::ErrorCallback on_error = {});

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace swm
