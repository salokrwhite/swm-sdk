#pragma once

#include <string>
#include <functional>
#include <optional>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace swm {

class FeedbackDisabledError : public std::runtime_error {
public:
  explicit FeedbackDisabledError(const std::string& message = "feedback disabled")
      : std::runtime_error(message) {}
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
  Client(std::string base_url, std::string app_key);

  std::string channel;
  std::string platform;
  std::string arch;
  std::string device_id;
  nlohmann::json attributes = nlohmann::json::object();
  int retries = 2;
  int backoff_ms = 500;
  std::function<bool(const std::string&, const std::string&)> signature_verifier;

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
  std::string app_key_;
};

} 
