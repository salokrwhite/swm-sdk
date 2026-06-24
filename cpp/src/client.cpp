#include "swm_sdk/client.hpp"

#include <cpr/cpr.h>
#include <cpr/util.h>
#include <openssl/evp.h>
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <utility>
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

// Minimal SHA256 (public domain, adapted) producing the raw 32-byte digest.
std::string sha256_raw(const std::string& data) {
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

  std::string out;
  out.reserve(32);
  for (int i = 0; i < 8; ++i) {
    for (int j = 3; j >= 0; --j) {
      out.push_back(static_cast<char>((h[i] >> (j * 8)) & 0xff));
    }
  }
  return out;
}

std::string to_hex(const std::string& bytes) {
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    out.push_back(hex[(b >> 4) & 0xf]);
    out.push_back(hex[b & 0xf]);
  }
  return out;
}

std::string sha256_hex(const std::string& data) {
  return to_hex(sha256_raw(data));
}

std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
  const size_t B = 64;
  std::string k = key;
  if (k.size() > B) k = sha256_raw(k);
  if (k.size() < B) k.resize(B, '\0');
  std::string ipad(B, 0x36), opad(B, 0x5c);
  for (size_t i = 0; i < B; ++i) {
    ipad[i] = static_cast<char>(ipad[i] ^ k[i]);
    opad[i] = static_cast<char>(opad[i] ^ k[i]);
  }
  std::string inner = sha256_raw(ipad + msg);
  return to_hex(sha256_raw(opad + inner));
}

long long now_unix() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string gen_nonce() {
  std::random_device rd;
  std::mt19937 g(rd());
  std::uniform_int_distribution<int> d(0, 15);
  static const char* hexd = "0123456789abcdef";
  const std::string fmt = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  std::string u;
  u.reserve(fmt.size());
  for (char c : fmt) {
    if (c == 'x') u.push_back(hexd[d(g)]);
    else if (c == 'y') u.push_back(hexd[(d(g) & 0x3) | 0x8]);
    else u.push_back(c);
  }
  return u;
}

std::string escape_rfc3986(const std::string& s) {
  static const char* hexd = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hexd[c >> 4]);
      out.push_back(hexd[c & 0xf]);
    }
  }
  return out;
}

std::string canonical_query(std::vector<std::pair<std::string, std::string>> pairs) {
  std::sort(pairs.begin(), pairs.end());
  std::string out;
  for (size_t i = 0; i < pairs.size(); ++i) {
    if (i) out.push_back('&');
    out += escape_rfc3986(pairs[i].first) + "=" + escape_rfc3986(pairs[i].second);
  }
  return out;
}

std::string hex_decode(const std::string& s) {
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    int hi = val(s[i]), lo = val(s[i + 1]);
    if (hi < 0 || lo < 0) return std::string();
    out.push_back(static_cast<char>((hi << 4) | lo));
  }
  return out;
}

std::string base64_decode(const std::string& in) {
  static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; ++i) T[static_cast<unsigned char>(chars[i])] = i;
  std::string out;
  int val = 0, valb = -8;
  for (unsigned char c : in) {
    if (c == '=') break;
    if (T[c] == -1) continue;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::string decode_key_material(const std::string& value) {
  std::string s = value;
  // trim
  size_t a = s.find_first_not_of(" \t\r\n");
  size_t b = s.find_last_not_of(" \t\r\n");
  s = (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
  if (s.empty()) throw AuthzError(kApiErrorCodeAuthzInvalid, "empty key material");
  bool all_hex = (s.size() % 2 == 0);
  if (all_hex) {
    for (char c : s) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) { all_hex = false; break; }
    }
  }
  return all_hex ? hex_decode(s) : base64_decode(s);
}

// Must match backend internal/auth/authz.go authzCanonical byte-for-byte.
std::string authz_canonical(const std::string& app_id, const AuthzEnvelope& env) {
  std::ostringstream os;
  os << "authz_v1" << "\n"
     << "app_id:" << app_id << "\n"
     << "device_id:" << env.device_id << "\n"
     << "nonce:" << env.nonce << "\n"
     << "decision:" << env.decision << "\n"
     << "reason:" << env.reason << "\n"
     << "issued_at:" << env.issued_at << "\n"
     << "expires_at:" << env.expires_at << "\n"
     << "key_id:" << env.key_id;
  return os.str();
}

bool ed25519_verify(const std::string& pub, const std::string& msg, const std::string& sig) {
  if (pub.size() != 32) return false;
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(pub.data()), pub.size());
  if (!pkey) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = false;
  if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    int rc = EVP_DigestVerify(
        ctx,
        reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    ok = (rc == 1);
  }
  if (ctx) EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

cpr::Header make_signed_header(const std::string& app_id, const std::string& app_secret,
                               const std::string& method, const std::string& path,
                               const std::string& canonical_q, const std::string& body,
                               std::string& out_nonce) {
  long long ts = now_unix();
  std::string nonce = gen_nonce();
  std::string canonical = method + "\n" + path + "\n" + canonical_q + "\n" +
                          sha256_hex(body) + "\n" + std::to_string(ts) + "\n" + nonce + "\n" + app_id;
  std::string sig = hmac_sha256_hex(app_secret, canonical);
  out_nonce = nonce;
  return cpr::Header{
    {"X-App-Id", app_id},
    {"X-Timestamp", std::to_string(ts)},
    {"X-Nonce", nonce},
    {"X-Signature", sig},
    {"X-Sign-Version", "v1"}
  };
}

std::optional<AuthzEnvelope> parse_authz_json(const nlohmann::json& a) {
  if (!a.is_object()) return std::nullopt;
  AuthzEnvelope e;
  e.decision = a.value("decision", "");
  e.nonce = a.value("nonce", "");
  e.device_id = a.value("device_id", "");
  e.issued_at = a.value("issued_at", 0LL);
  e.expires_at = a.value("expires_at", 0LL);
  e.key_id = a.value("key_id", "");
  e.reason = a.value("reason", "");
  e.signature = a.value("signature", "");
  return e;
}

std::optional<AuthzEnvelope> extract_authz_from_body(const std::string& body) {
  auto j = nlohmann::json::parse(body, nullptr, false);
  if (j.is_discarded() || !j.is_object() || !j.contains("authz")) return std::nullopt;
  return parse_authz_json(j["authz"]);
}

void verify_authz_impl(bool require_authz, const std::map<std::string, std::string>& keys, int skew_secs,
                       const std::string& app_id, const std::string& device_id,
                       const std::optional<AuthzEnvelope>& env_opt, const std::string& request_nonce) {
  if (!require_authz) return;
  if (!env_opt.has_value()) throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization missing");
  const AuthzEnvelope& env = *env_opt;
  if (request_nonce.empty() || env.nonce != request_nonce) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization nonce mismatch");
  }
  if (env.device_id != device_id) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization device mismatch");
  }
  int skew = skew_secs > 0 ? skew_secs : 120;
  long long now = now_unix();
  if (env.expires_at <= 0 || now > env.expires_at + skew) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization expired");
  }
  auto it = keys.find(env.key_id);
  if (it == keys.end() || it->second.empty()) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization key unknown: " + env.key_id);
  }
  if (env.signature.empty()) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization signature missing");
  }
  std::string pub = decode_key_material(it->second);
  if (pub.size() != 32) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization public key invalid");
  }
  std::string sig = decode_key_material(env.signature);
  std::string msg = authz_canonical(app_id, env);
  if (!ed25519_verify(pub, msg, sig)) {
    throw AuthzError(kApiErrorCodeAuthzInvalid, "authorization signature invalid");
  }
  if (env.decision != "allow") {
    std::string reason = env.reason.empty() ? "access denied" : env.reason;
    throw AuthzError(kApiErrorCodeAuthzDenied, "authorization denied: " + reason);
  }
}

std::string read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

void mp_field(std::string& body, const std::string& boundary, const std::string& name, const std::string& value) {
  body += "--" + boundary + "\r\n";
  body += "Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n";
  body += value;
  body += "\r\n";
}

void mp_file(std::string& body, const std::string& boundary, const std::string& name,
             const std::string& filename, const std::string& content) {
  body += "--" + boundary + "\r\n";
  body += "Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\"\r\n";
  body += "Content-Type: application/octet-stream\r\n\r\n";
  body += content;
  body += "\r\n";
}

} // namespace

Client::Client(std::string base_url, std::string app_id, std::string app_secret)
  : base_url_(trim_trailing_slash(base_url)), app_id_(std::move(app_id)), app_secret_(std::move(app_secret)) {}

UpdateCheckResponse Client::check_update(const std::string& current_version, const std::optional<int>& version_code) {
  nlohmann::json body = {
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
  std::string body_str = body.dump();

  cpr::Response res;
  std::string nonce;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    cpr::Header hdr = make_signed_header(app_id_, app_secret_, "POST", "/api/client/update-check", "", body_str, nonce);
    hdr["Content-Type"] = "application/json";
    res = cpr::Post(cpr::Url{base_url_ + "/api/client/update-check"}, hdr, cpr::Body{body_str});
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
  if (json.contains("authz")) {
    out.authz = parse_authz_json(json["authz"]);
  }
  // Fail closed: when require_authz, the response must carry a valid signed "allow".
  verify_authz_impl(require_authz, authz_public_keys, authz_clock_skew_seconds, app_id_, device_id, out.authz, nonce);
  if (signature_verifier && !out.signature.empty() && !out.checksum_sha256.empty()) {
    if (!signature_verifier(out.checksum_sha256, out.signature)) {
      throw std::runtime_error("signature verification failed");
    }
  }
  return out;
}

void Client::report_event(const std::string& event_name, const nlohmann::json& properties) {
  nlohmann::json body = {
    {"device_id", device_id},
    {"event_name", event_name},
    {"channel_code", channel},
    {"properties", properties},
    {"attributes", attributes}
  };
  std::string body_str = body.dump();

  cpr::Response res;
  std::string nonce;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    cpr::Header hdr = make_signed_header(app_id_, app_secret_, "POST", "/api/client/events", "", body_str, nonce);
    hdr["Content-Type"] = "application/json";
    res = cpr::Post(cpr::Url{base_url_ + "/api/client/events"}, hdr, cpr::Body{body_str});
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }

  if (res.status_code >= 300) {
    throw std::runtime_error("report event failed: " + std::to_string(res.status_code));
  }
  verify_authz_impl(require_authz, authz_public_keys, authz_clock_skew_seconds, app_id_, device_id, extract_authz_from_body(res.text), nonce);
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
  std::string app_id = app_id_;
  std::string app_secret = app_secret_;
  bool require_authz_v = require_authz;
  std::map<std::string, std::string> keys = authz_public_keys;
  int skew = authz_clock_skew_seconds;
  std::string base_url = base_url_;
  std::thread([=]() {
    int backoff = std::max(300, options.reconnect_backoff_ms);
    int max_backoff = std::max(backoff, options.reconnect_max_backoff_ms);
    std::mt19937 rng(std::random_device{}());

    while (!stop_flag->load()) {
      try {
        std::vector<std::pair<std::string, std::string>> params = {
          {"device_id", stream_device},
          {"channel_code", channel_code},
          {"platform", stream_platform},
          {"arch", stream_arch}
        };
        if (!options.current_version.empty()) {
          params.push_back({"current_version", options.current_version});
        }
        if (options.version_code.has_value()) {
          params.push_back({"version_code", std::to_string(options.version_code.value())});
        }
        std::string query = canonical_query(params);
        std::string nonce;
        cpr::Header hdr = make_signed_header(app_id, app_secret, "GET", "/api/client/updates/stream", query, "", nonce);

        auto res = cpr::Get(cpr::Url{base_url + "/api/client/updates/stream?" + query}, hdr);
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
        // When require_authz, ignore pushed events until a valid authz event proves
        // the stream comes from the real server.
        bool authz_ok = !require_authz_v;
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
            if (!data.empty()) {
              if (event_type == "authz") {
                if (require_authz_v) {
                  auto j = nlohmann::json::parse(data, nullptr, false);
                  if (j.is_discarded()) {
                    if (options.on_error) options.on_error("authorization malformed");
                    return;
                  }
                  try {
                    verify_authz_impl(require_authz_v, keys, skew, app_id, stream_device, parse_authz_json(j), nonce);
                  } catch (const std::exception& ex) {
                    if (options.on_error) options.on_error(ex.what());
                    return;  // fatal: fake server / revoked device, don't reconnect
                  }
                  authz_ok = true;
                }
              } else if (event_type != "connected" && authz_ok) {
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
  std::string body_str = body.dump();

  cpr::Response res;
  std::string nonce;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    cpr::Header hdr = make_signed_header(app_id_, app_secret_, "POST", "/api/client/heartbeat", "", body_str, nonce);
    hdr["Content-Type"] = "application/json";
    res = cpr::Post(cpr::Url{base_url_ + "/api/client/heartbeat"}, hdr, cpr::Body{body_str});
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }

  if (res.status_code >= 300) {
    throw std::runtime_error("heartbeat failed: " + std::to_string(res.status_code));
  }
  verify_authz_impl(require_authz, authz_public_keys, authz_clock_skew_seconds, app_id_, device_id, extract_authz_from_body(res.text), nonce);
}

void Client::report_events(const nlohmann::json& events) {
  nlohmann::json body = {
    {"events", events}
  };
  std::string body_str = body.dump();
  cpr::Response res;
  std::string nonce;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    cpr::Header hdr = make_signed_header(app_id_, app_secret_, "POST", "/api/client/events", "", body_str, nonce);
    hdr["Content-Type"] = "application/json";
    res = cpr::Post(cpr::Url{base_url_ + "/api/client/events"}, hdr, cpr::Body{body_str});
    if (res.error.code == cpr::ErrorCode::OK) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms * (1 << attempt)));
  }
  if (res.status_code >= 300) {
    throw std::runtime_error("report event failed: " + std::to_string(res.status_code));
  }
  verify_authz_impl(require_authz, authz_public_keys, authz_clock_skew_seconds, app_id_, device_id, extract_authz_from_body(res.text), nonce);
}

void Client::report_feedback(const std::string& content,
                             const std::optional<int>& rating,
                             const std::string& contact,
                             const std::vector<std::string>& attachments,
                             const nlohmann::json& metadata) {
  if (content.empty() || std::all_of(content.begin(), content.end(), [](unsigned char c) { return std::isspace(c); })) {
    throw std::runtime_error("content required");
  }

  // Build the multipart body manually so we can sign the exact bytes sent.
  std::string boundary = "----swm-" + gen_nonce();
  std::string body;
  mp_field(body, boundary, "device_id", device_id);
  mp_field(body, boundary, "content", content);
  if (!channel.empty()) {
    mp_field(body, boundary, "channel_code", channel);
  }
  if (rating.has_value()) {
    mp_field(body, boundary, "rating", std::to_string(rating.value()));
  }
  if (!contact.empty()) {
    mp_field(body, boundary, "contact", contact);
  }

  nlohmann::json merged = metadata.is_object() ? metadata : nlohmann::json::object();
  if (!attributes.is_null() && !attributes.empty() && !merged.contains("attributes")) {
    merged["attributes"] = attributes;
  }
  if (merged.contains("app_version")) {
    if (merged["app_version"].is_string()) {
      mp_field(body, boundary, "app_version", merged["app_version"].get<std::string>());
    } else {
      mp_field(body, boundary, "app_version", merged["app_version"].dump());
    }
  }
  if (!merged.empty()) {
    mp_field(body, boundary, "metadata", merged.dump());
  }

  for (const auto& file_path : attachments) {
    if (file_path.empty() || !std::filesystem::exists(file_path)) {
      continue;
    }
    std::string fname = std::filesystem::path(file_path).filename().string();
    mp_file(body, boundary, "attachments", fname, read_file(file_path));
  }
  body += "--" + boundary + "--\r\n";

  cpr::Response res;
  std::string nonce;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    cpr::Header hdr = make_signed_header(app_id_, app_secret_, "POST", "/api/client/feedback", "", body, nonce);
    hdr["Content-Type"] = "multipart/form-data; boundary=" + boundary;
    res = cpr::Post(cpr::Url{base_url_ + "/api/client/feedback"}, hdr, cpr::Body{body});
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
  verify_authz_impl(require_authz, authz_public_keys, authz_clock_skew_seconds, app_id_, device_id, extract_authz_from_body(res.text), nonce);
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
