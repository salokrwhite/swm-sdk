#pragma once

#include <string>
#include <functional>
#include <optional>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace swm {

inline constexpr const char* kApiErrorCodeAuthzInvalid = "authz_invalid";
inline constexpr const char* kApiErrorCodeAuthzDenied = "authz_denied";

class FeedbackDisabledError : public std::runtime_error {
public:
  explicit FeedbackDisabledError(const std::string& message = "feedback disabled")
      : std::runtime_error(message) {}
};

// Thrown when a required authorization verdict is missing or invalid (fail closed).
class AuthzError : public std::runtime_error {
public:
  AuthzError(std::string code, const std::string& message)
      : std::runtime_error(code + ": " + message), code(std::move(code)) {}
  std::string code;
};

// Device-bound authorization verdict signed by the server with an Ed25519 key.
struct AuthzEnvelope {
  std::string decision;
  std::string nonce;
  std::string device_id;
  long long issued_at = 0;
  long long expires_at = 0;
  std::string key_id;
  std::string reason;
  std::string signature;
};

inline constexpr const char* kControlEventShutdown = "device_shutdown";
inline constexpr const char* kControlEventMaintenanceScheduled = "maintenance_scheduled";
inline constexpr const char* kControlEventMaintenanceCancelled = "maintenance_cancelled";

struct Maintenance {
  bool enabled = false;
  std::string start_at;
  std::string message;
  bool active = false;
};

struct UpdateCheckResponse {
  bool update_available = false;
  bool mandatory = false;
  long long heartbeat_interval_seconds = 0;
  std::string release_id;
  std::string version;
  std::string notes;
  std::string download_url;
  std::string checksum_sha256;
  std::string signature;
  long long size = 0;
  bool rollback_allowed = false;
  std::string release_notes_url;
  std::optional<Maintenance> maintenance;
  std::optional<AuthzEnvelope> authz;
};

struct UpdatePushEvent {
  std::string id;
  std::string event_type;
  std::string org_id;
  std::string app_id;
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
  std::string channel_code;
  std::string platform;
  std::string arch;
  std::string device_id;
  std::string current_version;
  std::optional<int> version_code = std::nullopt;
  bool reconnect = true;
  int reconnect_backoff_ms = 1500;
  int reconnect_max_backoff_ms = 20000;
  bool jitter = true;
  std::function<void(const std::string&)> on_error;
};

class UpdateWatchHandle {
public:
  UpdateWatchHandle() = default;
  explicit UpdateWatchHandle(std::shared_ptr<std::atomic<bool>> stop_flag) : stop_flag_(std::move(stop_flag)) {}
  void stop() const {
    if (stop_flag_) {
      stop_flag_->store(true);
    }
  }
private:
  std::shared_ptr<std::atomic<bool>> stop_flag_;
};

class Client {
public:
  Client(std::string base_url, std::string app_id, std::string app_secret);

  std::string channel;
  std::string platform;
  std::string arch;
  std::string device_id;
  nlohmann::json attributes = nlohmann::json::object();
  int retries = 2;
  int backoff_ms = 500;
  std::function<bool(const std::string&, const std::string&)> signature_verifier;
  // When true, every call that can carry a signed verdict fails closed unless the
  // response has a valid Ed25519 "allow" bound to this request + device.
  bool require_authz = false;
  // key_id -> Ed25519 public key (hex or base64).
  std::map<std::string, std::string> authz_public_keys;
  int authz_clock_skew_seconds = 120;

  UpdateCheckResponse check_update(const std::string& current_version, const std::optional<int>& version_code = std::nullopt);
  void report_event(const std::string& event_name, const nlohmann::json& properties = nlohmann::json::object());
  void report_heartbeat(const std::string& app_version = "", const std::string& user_id = "");
  void report_events(const nlohmann::json& events);
  void report_feedback(const std::string& content,
                       const std::optional<int>& rating = std::nullopt,
                       const std::string& contact = "",
                       const std::vector<std::string>& attachments = {},
                       const nlohmann::json& metadata = nlohmann::json::object());
  void download(const std::string& url, const std::string& dest_path, const std::string& checksum_sha256 = "", const std::string& signature = "");
  UpdateWatchHandle start_update_stream(const UpdateStreamOptions& options, const std::function<void(const UpdatePushEvent&)>& on_event);
  UpdateWatchHandle watch_updates(const UpdateStreamOptions& options, const std::function<void(const UpdateCheckResponse&)>& on_update_available);

private:
  std::string base_url_;
  std::string app_id_;
  std::string app_secret_;
};

} 
