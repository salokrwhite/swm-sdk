#include "swm_sdk/client.hpp"

#include <cpr/cpr.h>
#include <cpr/util.h>
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sstream>
#include <random>

namespace swm {

namespace {
std::string trim_trailing_slash(const std::string& input) {
  if (!input.empty() && input.back() == '/') {
    return input.substr(0, input.size() - 1);
  }
  return input;
}

bool is_feedback_disabled_body(const std::string& body) {
  if (body.empty()) {
    return false;
  }
  try {
    auto payload = nlohmann::json::parse(body);
    if (!payload.contains("error")) {
      return false;
    }
    const auto& err = payload["error"];
    if (err.is_object() && err.contains("code") && err["code"].is_string()) {
      std::string code = err["code"].get<std::string>();
      std::transform(code.begin(), code.end(), code.begin(), [](unsigned char c) { return std::tolower(c); });
      return code == "feedback_disabled";
    }
    if (err.is_string()) {
      std::string code = err.get<std::string>();
      std::transform(code.begin(), code.end(), code.begin(), [](unsigned char c) { return std::tolower(c); });
      return code == "feedback_disabled";
    }
  } catch (...) {
    return false;
  }
  return false;
}

std::string sha256_hex(const std::string& data) {
  // Minimal SHA256 implementation (public domain)
  // Source: https://github.com/B-Con/crypto-algorithms (adapted)
  // To keep dependencies minimal, we embed a tiny implementation here.
  static const unsigned int k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };
  auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };

  uint64_t bitlen = static_cast<uint64_t>(data.size()) * 8;
  std::vector<uint8_t> msg(data.begin(), data.end());
  msg.push_back(0x80);
  while ((msg.size() % 64) != 56) msg.push_back(0x00);
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<uint8_t>((bitlen >> (i * 8)) & 0xff));

  uint32_t h[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };

  for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = (msg[chunk + i * 4] << 24) | (msg[chunk + i * 4 + 1] << 16) | (msg[chunk + i * 4 + 2] << 8) | (msg[chunk + i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
      uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;

      hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (int i = 0; i < 8; ++i) {
    for (int j = 3; j >= 0; --j) {
      uint8_t byte = (h[i] >> (j * 8)) & 0xff;
      out.push_back(hex[(byte >> 4) & 0xf]);
      out.push_back(hex[byte & 0xf]);
    }
  }
  return out;
}

} // namespace

Client::Client(std::string base_url, std::string app_key)
  : base_url_(trim_trailing_slash(base_url)), app_key_(std::move(app_key)) {}

UpdateCheckResponse Client::check_update(const std::string& current_version, const std::optional<int>& version_code) {
  nlohmann::json body = {
    {"app_key", app_key_},
    {"channel_code", channel},
    {"current_version", current_version},
    {"platform", platform},
    {"arch", arch},
    {"device_id", device_id},
    {"attributes", attributes}
  };
  if (version_code.has_value()) {
    body["version_code"] = version_code.value();
  }

  cpr::Response res;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    res = cpr::Post(
      cpr::Url{base_url_ + "/api/client/update-check"},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{body.dump()}
    );
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }

  if (res.status_code >= 300) {
    throw std::runtime_error("update check failed: " + std::to_string(res.status_code));
  }

  auto json = nlohmann::json::parse(res.text);
  UpdateCheckResponse out;
  out.update_available = json.value("update_available", false);
  out.mandatory = json.value("mandatory", false);
  out.release_id = json.value("release_id", "");
  out.version = json.value("version", "");
  out.notes = json.value("notes", "");
  out.heartbeat_interval_seconds = json.value("heartbeat_interval_seconds", 0LL);
  out.download_url = json.value("download_url", "");
  out.checksum_sha256 = json.value("checksum_sha256", "");
  out.signature = json.value("signature", "");
  out.size = json.value("size", 0LL);
  out.rollback_allowed = json.value("rollback_allowed", false);
  out.release_notes_url = json.value("release_notes_url", "");
  if (json.contains("maintenance") && json["maintenance"].is_object()) {
    const auto& m = json["maintenance"];
    Maintenance maint;
    maint.enabled = m.value("enabled", false);
    maint.start_at = m.value("start_at", "");
    maint.message = m.value("message", "");
    maint.active = m.value("active", false);
    out.maintenance = maint;
  }
  if (signature_verifier && !out.signature.empty() && !out.checksum_sha256.empty()) {
    if (!signature_verifier(out.checksum_sha256, out.signature)) {
      throw std::runtime_error("signature verification failed");
    }
  }
  return out;
}

void Client::report_event(const std::string& event_name, const nlohmann::json& properties) {
  nlohmann::json body = {
    {"app_key", app_key_},
    {"device_id", device_id},
    {"event_name", event_name},
    {"channel_code", channel},
    {"properties", properties},
    {"attributes", attributes}
  };

  cpr::Response res;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    res = cpr::Post(
      cpr::Url{base_url_ + "/api/client/events"},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{body.dump()}
    );
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }

  if (res.status_code >= 300) {
    throw std::runtime_error("report event failed: " + std::to_string(res.status_code));
  }
}

UpdateWatchHandle Client::start_update_stream(const UpdateStreamOptions& options, const std::function<void(const UpdatePushEvent&)>& on_event) {
  std::string channel_code = options.channel_code.empty() ? channel : options.channel_code;
  std::string stream_platform = options.platform.empty() ? platform : options.platform;
  std::string stream_arch = options.arch.empty() ? arch : options.arch;
  std::string stream_device = options.device_id.empty() ? device_id : options.device_id;
  if (channel_code.empty() || stream_platform.empty() || stream_arch.empty() || stream_device.empty()) {
    throw std::runtime_error("channel_code/platform/arch/device_id required");
  }

  auto stop_flag = std::make_shared<std::atomic<bool>>(false);
  std::thread([=]() {
    int backoff = std::max(300, options.reconnect_backoff_ms);
    int max_backoff = std::max(backoff, options.reconnect_max_backoff_ms);
    std::mt19937 rng(std::random_device{}());

    while (!stop_flag->load()) {
      try {
        std::ostringstream qs;
        qs << "?app_key=" << cpr::util::urlEncode(app_key_)
           << "&channel_code=" << cpr::util::urlEncode(channel_code)
           << "&platform=" << cpr::util::urlEncode(stream_platform)
           << "&arch=" << cpr::util::urlEncode(stream_arch)
           << "&device_id=" << cpr::util::urlEncode(stream_device);
        if (!options.current_version.empty()) {
          qs << "&current_version=" << cpr::util::urlEncode(options.current_version);
        }
        if (options.version_code.has_value()) {
          qs << "&version_code=" << options.version_code.value();
        }

        auto res = cpr::Get(cpr::Url{base_url_ + "/api/client/updates/stream" + qs.str()});
        if (res.status_code == 401 || res.status_code == 403) {
          if (options.on_error) {
            options.on_error("stream unauthorized: " + std::to_string(res.status_code));
          }
          return;
        }
        if (res.status_code >= 300) {
          throw std::runtime_error("stream failed: " + std::to_string(res.status_code));
        }

        backoff = std::max(300, options.reconnect_backoff_ms);
        std::istringstream stream(res.text);
        std::string line;
        std::string event_type;
        std::string data;
        while (std::getline(stream, line)) {
          if (stop_flag->load()) {
            return;
          }
          if (!line.empty() && line.back() == '\r') {
            line.pop_back();
          }
          if (line.empty()) {
            if (!data.empty() && event_type != "connected") {
              auto payload = nlohmann::json::parse(data, nullptr, false);
              if (!payload.is_discarded()) {
                UpdatePushEvent evt;
                evt.id = payload.value("id", "");
                evt.event_type = payload.value("event_type", "");
                evt.org_id = payload.value("org_id", "");
                evt.app_id = payload.value("app_id", "");
                evt.channel_code = payload.value("channel_code", "");
                evt.platform = payload.value("platform", "");
                evt.arch = payload.value("arch", "");
                evt.release_id = payload.value("release_id", "");
                evt.published_at = payload.value("published_at", "");
                evt.reason = payload.value("reason", "");
                evt.message = payload.value("message", "");
                evt.maintenance_start_at = payload.value("maintenance_start_at", "");
                if (on_event) {
                  on_event(evt);
                }
              }
            }
            event_type.clear();
            data.clear();
            continue;
          }
          if (line.rfind(":", 0) == 0) {
            continue;
          }
          if (line.rfind("event:", 0) == 0) {
            event_type = line.substr(6);
            event_type.erase(0, event_type.find_first_not_of(" \t"));
          } else if (line.rfind("data:", 0) == 0) {
            std::string chunk = line.substr(5);
            chunk.erase(0, chunk.find_first_not_of(" \t"));
            if (!data.empty()) {
              data += "\n";
            }
            data += chunk;
          }
        }
      } catch (const std::exception& ex) {
        if (options.on_error) {
          options.on_error(ex.what());
        }
      }

      if (!options.reconnect) {
        return;
      }
      int wait_ms = backoff;
      if (options.jitter) {
        std::uniform_int_distribution<int> dist(0, std::max(1, wait_ms / 2));
        wait_ms += dist(rng);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
      backoff = std::min(max_backoff, backoff * 2);
    }
  }).detach();

  return UpdateWatchHandle(stop_flag);
}

UpdateWatchHandle Client::watch_updates(const UpdateStreamOptions& options, const std::function<void(const UpdateCheckResponse&)>& on_update_available) {
  return start_update_stream(options, [this, options, on_update_available](const UpdatePushEvent&) {
    try {
      auto resp = check_update(options.current_version, options.version_code);
      if (resp.update_available && on_update_available) {
        on_update_available(resp);
      }
    } catch (const std::exception& ex) {
      if (options.on_error) {
        options.on_error(ex.what());
      }
    }
  });
}

void Client::report_heartbeat(const std::string& app_version, const std::string& user_id) {
  nlohmann::json body = {
    {"app_key", app_key_},
    {"device_id", device_id}
  };
  if (!channel.empty()) {
    body["channel_code"] = channel;
  }
  if (!app_version.empty()) {
    body["app_version"] = app_version;
  }
  if (!platform.empty()) {
    body["platform"] = platform;
  }
  if (!arch.empty()) {
    body["arch"] = arch;
  }
  if (!user_id.empty()) {
    body["user_id"] = user_id;
  }
  if (!attributes.is_null() && !attributes.empty()) {
    body["attributes"] = attributes;
  }

  cpr::Response res;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    res = cpr::Post(
      cpr::Url{base_url_ + "/api/client/heartbeat"},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{body.dump()}
    );
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }

  if (res.status_code >= 300) {
    throw std::runtime_error("heartbeat failed: " + std::to_string(res.status_code));
  }
}

void Client::report_events(const nlohmann::json& events) {
  nlohmann::json body = {
    {"app_key", app_key_},
    {"events", events}
  };
  cpr::Response res;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    res = cpr::Post(
      cpr::Url{base_url_ + "/api/client/events"},
      cpr::Header{{"Content-Type", "application/json"}},
      cpr::Body{body.dump()}
    );
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }
  if (res.status_code >= 300) {
    throw std::runtime_error("report event failed: " + std::to_string(res.status_code));
  }
}

void Client::report_feedback(const std::string& content,
                             const std::optional<int>& rating,
                             const std::string& contact,
                             const std::vector<std::string>& attachments,
                             const nlohmann::json& metadata) {
  if (content.empty() || std::all_of(content.begin(), content.end(), [](unsigned char c) { return std::isspace(c); })) {
    throw std::runtime_error("content required");
  }

  auto build_multipart = [&]() {
    cpr::Multipart multipart{{"app_key", app_key_}, {"device_id", device_id}, {"content", content}};
    if (!channel.empty()) {
      multipart.parts.push_back({"channel_code", channel});
    }
    if (rating.has_value()) {
      multipart.parts.push_back({"rating", std::to_string(rating.value())});
    }
    if (!contact.empty()) {
      multipart.parts.push_back({"contact", contact});
    }

    nlohmann::json merged = metadata.is_null() ? nlohmann::json::object() : metadata;
    if (!merged.is_object()) {
      merged = nlohmann::json::object();
    }
    if (!attributes.is_null() && !attributes.empty() && !merged.contains("attributes")) {
      merged["attributes"] = attributes;
    }
    if (merged.contains("app_version")) {
      if (merged["app_version"].is_string()) {
        multipart.parts.push_back({"app_version", merged["app_version"].get<std::string>()});
      } else {
        multipart.parts.push_back({"app_version", merged["app_version"].dump()});
      }
    }
    if (!merged.empty()) {
      multipart.parts.push_back({"metadata", merged.dump()});
    }

    for (const auto& file_path : attachments) {
      if (file_path.empty()) {
        continue;
      }
      multipart.parts.push_back({"attachments", cpr::File{file_path}});
    }
    return multipart;
  };

  cpr::Response res;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    res = cpr::Post(
      cpr::Url{base_url_ + "/api/client/feedback"},
      build_multipart()
    );
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }
  if (res.status_code >= 300) {
    if (is_feedback_disabled_body(res.text)) {
      throw FeedbackDisabledError();
    }
    throw std::runtime_error("report feedback failed: " + std::to_string(res.status_code));
  }
}

void Client::download(const std::string& url, const std::string& dest_path, const std::string& checksum_sha256, const std::string& signature) {
  auto res = cpr::Get(cpr::Url{url});
  if (res.status_code >= 300) {
    throw std::runtime_error("download failed: " + std::to_string(res.status_code));
  }

  std::filesystem::path out_path(dest_path);
  if (out_path.has_parent_path()) {
    std::filesystem::create_directories(out_path.parent_path());
  }
  std::ofstream out(dest_path, std::ios::binary);
  if (!out.is_open()) {
    throw std::runtime_error("failed to open file");
  }
  out.write(res.text.data(), static_cast<std::streamsize>(res.text.size()));
  out.close();

  if (!checksum_sha256.empty()) {
    std::string got = sha256_hex(res.text);
    if (got != checksum_sha256) {
      throw std::runtime_error("checksum mismatch: " + got + " != " + checksum_sha256);
    }
  }
  if (signature_verifier && !signature.empty() && !checksum_sha256.empty()) {
    if (!signature_verifier(checksum_sha256, signature)) {
      throw std::runtime_error("signature verification failed");
    }
  }
}

} // namespace swm
