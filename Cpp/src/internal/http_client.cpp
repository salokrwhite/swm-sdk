#include "internal/http_client.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

#include <array>
#include <algorithm>
#include <cctype>

namespace swm::internal {
namespace {

class InternetHandle final {
public:
    InternetHandle() = default;
    explicit InternetHandle(HINTERNET value) : value_(value) {}
    ~InternetHandle() {
        if (value_ != nullptr) {
            WinHttpCloseHandle(value_);
        }
    }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    InternetHandle(InternetHandle&& other) noexcept : value_(other.value_) {
        other.value_ = nullptr;
    }
    InternetHandle& operator=(InternetHandle&& other) noexcept {
        if (this != &other) {
            if (value_ != nullptr) {
                WinHttpCloseHandle(value_);
            }
            value_ = other.value_;
            other.value_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] HINTERNET get() const noexcept { return value_; }
    [[nodiscard]] HINTERNET* put() noexcept { return &value_; }

private:
    HINTERNET value_ = nullptr;
};

struct ParsedUrl {
    std::wstring scheme;
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    bool secure = false;
};

ParsedUrl parse_url(const std::string& url, const bool allow_insecure_http) {
    const auto wide = utf8_to_wide(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &components)) {
        throw Error(ErrorKind::Configuration, 0, {}, "URL is invalid");
    }
    ParsedUrl parsed;
    parsed.scheme.assign(components.lpszScheme, components.dwSchemeLength);
    parsed.host.assign(components.lpszHostName, components.dwHostNameLength);
    parsed.path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength > 0) {
        parsed.path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    parsed.port = components.nPort;
    parsed.secure = _wcsicmp(parsed.scheme.c_str(), L"https") == 0;
    if (!parsed.secure && !(allow_insecure_http && _wcsicmp(parsed.scheme.c_str(), L"http") == 0)) {
        throw Error(ErrorKind::Configuration, 0, {}, "HTTPS is required");
    }
    return parsed;
}

void set_timeouts(const HINTERNET session, const int timeout_ms) {
    const int value = std::max(timeout_ms, 1000);
    WinHttpSetTimeouts(session, value, value, value, value);
}

void add_request_headers(const HINTERNET request, const HttpHeaders& headers) {
    for (const auto& [name, value] : headers.values) {
        const auto line = utf8_to_wide(name + ": " + value);
        if (!WinHttpAddRequestHeaders(request, line.c_str(), static_cast<DWORD>(line.size()),
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
                "cannot add HTTP request header");
        }
    }
}

HttpHeaders parse_response_headers(const HINTERNET request) {
    DWORD size = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return {};
    }
    std::wstring raw(size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
            raw.data(), &size, WINHTTP_NO_HEADER_INDEX)) {
        return {};
    }
    HttpHeaders headers;
    std::size_t offset = 0;
    while (offset < raw.size()) {
        auto end = raw.find(L"\r\n", offset);
        if (end == std::wstring::npos) {
            break;
        }
        const auto line = raw.substr(offset, end - offset);
        offset = end + 2;
        if (line.empty()) {
            break;
        }
        const auto separator = line.find(L':');
        if (separator == std::wstring::npos) {
            continue;
        }
        headers.add(lower_ascii(wide_to_utf8(line.substr(0, separator))),
            trim_ascii(wide_to_utf8(line.substr(separator + 1))));
    }
    return headers;
}

HttpResponse read_response(const HINTERNET request, const std::size_t maximum_bytes,
    const std::stop_token& stop) {
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "cannot query HTTP status");
    }
    HttpResponse response;
    response.status_code = static_cast<int>(status);
    response.headers = parse_response_headers(request);
    std::array<std::uint8_t, 32 * 1024> buffer{};
    while (true) {
        throw_if_stopped(stop);
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), static_cast<DWORD>(buffer.size()), &read)) {
            throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
                "HTTP response read failed");
        }
        if (read == 0) {
            break;
        }
        if (response.body.size() + read > maximum_bytes) {
            throw Error(ErrorKind::Protocol, 0, {}, "HTTP response exceeds size limit");
        }
        response.body.insert(response.body.end(), buffer.begin(), buffer.begin() + read);
    }
    return response;
}

struct OpenRequest {
    InternetHandle session;
    InternetHandle connection;
    InternetHandle request;
};

OpenRequest open_request(HttpClient*, const bool allow_insecure_http,
    const std::wstring& user_agent, const HttpRequest& input) {
    const auto parsed = parse_url(input.url, allow_insecure_http);
    OpenRequest result;
    result.session = InternetHandle(WinHttpOpen(user_agent.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (result.session.get() == nullptr) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "WinHttpOpen failed");
    }
    set_timeouts(result.session.get(), input.timeout_ms);
    result.connection = InternetHandle(WinHttpConnect(result.session.get(),
        parsed.host.c_str(), parsed.port, 0));
    if (result.connection.get() == nullptr) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "WinHttpConnect failed");
    }
    const auto method = utf8_to_wide(input.method);
    result.request = InternetHandle(WinHttpOpenRequest(result.connection.get(), method.c_str(),
        parsed.path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, parsed.secure ? WINHTTP_FLAG_SECURE : 0));
    if (result.request.get() == nullptr) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "WinHttpOpenRequest failed");
    }
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(result.request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
        &redirect_policy, sizeof(redirect_policy));
    add_request_headers(result.request.get(), input.headers);
    return result;
}

void send(OpenRequest& request, const HttpRequest& input, const std::stop_token& stop) {
    throw_if_stopped(stop);
    const DWORD length = static_cast<DWORD>(input.body.size());
    if (!WinHttpSendRequest(request.request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            input.body.empty() ? WINHTTP_NO_REQUEST_DATA :
                const_cast<void*>(static_cast<const void*>(input.body.data())),
            length, length, 0)) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "WinHttpSendRequest failed");
    }
    throw_if_stopped(stop);
    if (!WinHttpReceiveResponse(request.request.get(), nullptr)) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "WinHttpReceiveResponse failed");
    }
}

} // namespace

void HttpHeaders::add(std::string name, std::string value) {
    values.emplace(lower_ascii(std::move(name)), std::move(value));
}

std::optional<std::string> HttpHeaders::get(const std::string_view name) const {
    const auto found = values.find(lower_ascii(std::string(name)));
    return found == values.end() ? std::nullopt : std::optional<std::string>(found->second);
}

struct ResponseStream::Impl {
    InternetHandle session;
    InternetHandle connection;
    InternetHandle request;
    int status_code = 0;
    HttpHeaders headers;
    bool closed = false;
};

ResponseStream::ResponseStream() = default;
ResponseStream::ResponseStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
ResponseStream::ResponseStream(ResponseStream&&) noexcept = default;
ResponseStream& ResponseStream::operator=(ResponseStream&&) noexcept = default;
ResponseStream::~ResponseStream() {
    close();
}

int ResponseStream::status_code() const noexcept {
    return impl_ ? impl_->status_code : 0;
}

const HttpHeaders& ResponseStream::headers() const noexcept {
    static const HttpHeaders empty;
    return impl_ ? impl_->headers : empty;
}

std::size_t ResponseStream::read(std::span<std::uint8_t> output,
    const std::stop_token& stop) {
    if (!impl_ || impl_->closed || output.empty()) {
        return 0;
    }
    throw_if_stopped(stop);
    DWORD read = 0;
    if (!WinHttpReadData(impl_->request.get(), output.data(),
            static_cast<DWORD>(output.size()), &read)) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "HTTP stream read failed");
    }
    if (read == 0) {
        impl_->closed = true;
    }
    return read;
}

void ResponseStream::close() noexcept {
    if (impl_) {
        impl_->closed = true;
        impl_.reset();
    }
}

HttpClient::HttpClient(const bool allow_insecure_http, std::wstring user_agent)
    : allow_insecure_http_(allow_insecure_http), user_agent_(std::move(user_agent)) {}

HttpClient::~HttpClient() = default;

HttpResponse HttpClient::request(const HttpRequest& input, const std::stop_token& stop) {
    auto opened = open_request(this, allow_insecure_http_, user_agent_, input);
    send(opened, input, stop);
    return read_response(opened.request.get(), input.maximum_response_bytes, stop);
}

ResponseStream HttpClient::stream(const HttpRequest& input, const std::stop_token& stop) {
    auto opened = open_request(this, allow_insecure_http_, user_agent_, input);
    send(opened, input, stop);
    auto impl = std::make_unique<ResponseStream::Impl>();
    impl->session = std::move(opened.session);
    impl->connection = std::move(opened.connection);
    impl->request = std::move(opened.request);
    DWORD status = 0;
    DWORD size = sizeof(status);
    if (!WinHttpQueryHeaders(impl->request.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
        throw Error(ErrorKind::Network, static_cast<int>(GetLastError()), {},
            "cannot query stream status");
    }
    impl->status_code = static_cast<int>(status);
    impl->headers = parse_response_headers(impl->request.get());
    return ResponseStream(std::move(impl));
}

} // namespace swm::internal
