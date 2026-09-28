#pragma once

#include "internal/common.hpp"

#include <map>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace swm::internal {

struct HttpHeaders {
    std::multimap<std::string, std::string, std::less<>> values;

    void add(std::string name, std::string value);
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
};

struct HttpResponse {
    int status_code = 0;
    HttpHeaders headers;
    Bytes body;
};

struct HttpRequest {
    std::string method;
    std::string url;
    HttpHeaders headers;
    Bytes body;
    int timeout_ms = 10000;
    std::size_t maximum_response_bytes = 16 * 1024 * 1024;
};

class ResponseStream final {
public:
    ResponseStream();
    ResponseStream(const ResponseStream&) = delete;
    ResponseStream& operator=(const ResponseStream&) = delete;
    ResponseStream(ResponseStream&&) noexcept;
    ResponseStream& operator=(ResponseStream&&) noexcept;
    ~ResponseStream();

    [[nodiscard]] int status_code() const noexcept;
    [[nodiscard]] const HttpHeaders& headers() const noexcept;
    std::size_t read(std::span<std::uint8_t> output, const std::stop_token& stop = {});
    void close() noexcept;

private:
    struct Impl;
    explicit ResponseStream(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
    friend class HttpClient;
};

class HttpClient final {
public:
    HttpClient(bool allow_insecure_http, std::wstring user_agent = L"SwmSdk/2.0");
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
    ~HttpClient();

    HttpResponse request(const HttpRequest& request, const std::stop_token& stop = {});
    ResponseStream stream(const HttpRequest& request, const std::stop_token& stop = {});

private:
    bool allow_insecure_http_;
    std::wstring user_agent_;
};

} // namespace swm::internal
