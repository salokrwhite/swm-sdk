#include "internal/multipart.hpp"

#include "internal/common.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

namespace swm::internal {
namespace {

std::string escape_multipart_name(std::string value) {
    std::string output;
    output.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '"') {
            output += "%22";
        } else if (value[index] != '\r' && value[index] != '\n') {
            output.push_back(value[index]);
        }
    }
    return output;
}

} // namespace

MultipartPayload build_feedback_payload(const std::string_view device_id,
    const std::string_view channel, const std::string_view default_version,
    const FeedbackRequest& request) {
    if (request.content.empty()) {
        throw Error(ErrorKind::Configuration, 0, {}, "feedback content is required");
    }
    if (request.rating.has_value() && (*request.rating < 1 || *request.rating > 5)) {
        throw Error(ErrorKind::Configuration, 0, {},
            "feedback rating must be between 1 and 5");
    }
    const auto attachment_count = static_cast<std::size_t>(std::count_if(
        request.attachments.begin(), request.attachments.end(),
        [](const std::filesystem::path& path) { return !path.empty(); }));
    if (attachment_count > 3) {
        throw Error(ErrorKind::Configuration, 0, {},
            "feedback supports at most 3 attachments");
    }
    if (!request.metadata.is_object()) {
        throw Error(ErrorKind::Configuration, 0, {},
            "feedback metadata must be a JSON object");
    }
    const auto boundary =
        "----------------------------" + hex_lower(random_bytes(12));
    Bytes body;
    const auto append = [&](const std::string_view value) {
        body.insert(body.end(), value.begin(), value.end());
    };
    const auto field = [&](const std::string_view name, const std::string_view value) {
        append("--" + boundary + "\r\n");
        append("Content-Disposition: form-data; name=\"" +
            escape_multipart_name(std::string(name)) + "\"\r\n\r\n");
        append(value);
        append("\r\n");
    };
    field("device_id", device_id);
    if (!channel.empty()) {
        field("channel_code", channel);
    }
    field("content", request.content);
    if (request.rating.has_value()) {
        field("rating", std::to_string(*request.rating));
    }
    if (!request.contact.empty()) {
        field("contact", request.contact);
    }
    const auto version = request.app_version.empty()
        ? std::string(default_version) : request.app_version;
    if (!version.empty()) {
        field("app_version", version);
    }
    if (!request.metadata.empty()) {
        field("metadata", request.metadata.dump());
    }
    for (const auto& path : request.attachments) {
        if (path.empty()) {
            continue;
        }
        if (!std::filesystem::exists(path)) {
            throw Error(ErrorKind::Configuration, 0, {},
                "feedback attachment was not found");
        }
        const auto size = std::filesystem::file_size(path);
        if (size > 5 * 1024 * 1024) {
            throw Error(ErrorKind::Configuration, 0, {},
                "feedback attachment exceeds 5 MiB");
        }
        append("--" + boundary + "\r\n");
        append("Content-Disposition: form-data; name=\"attachments\"; filename=\"" +
            escape_multipart_name(path.filename().string()) + "\"\r\n");
        append("Content-Type: application/octet-stream\r\n\r\n");
        std::ifstream stream(path, std::ios::binary);
        body.insert(body.end(), std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>());
        append("\r\n");
    }
    append("--" + boundary + "--\r\n");
    if (body.size() > 32 * 1024 * 1024) {
        throw Error(ErrorKind::Configuration, 0, {},
            "feedback payload exceeds 32 MiB");
    }
    return {std::move(body), "multipart/form-data; boundary=" + boundary};
}

} // namespace swm::internal
