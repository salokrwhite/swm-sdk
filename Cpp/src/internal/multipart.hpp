#pragma once

#include "swm/types.hpp"

#include <string>

namespace swm::internal {

struct MultipartPayload {
    Bytes body;
    std::string content_type;
};

MultipartPayload build_feedback_payload(std::string_view device_id,
    std::string_view channel, std::string_view default_version,
    const FeedbackRequest& request);

} // namespace swm::internal
