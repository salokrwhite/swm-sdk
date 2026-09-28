#pragma once

#include <cstdint>

namespace swm::internal {

class TrustedClock final {
public:
    [[nodiscard]] bool initialized() const noexcept;
    [[nodiscard]] std::int64_t now_unix_ms() const noexcept;
    [[nodiscard]] std::int64_t now_unix_seconds() const noexcept;
    void set_authoritative_time(std::int64_t server_time_ms,
        std::uint64_t request_started_tick_ms,
        std::uint64_t response_received_tick_ms);

    static std::uint64_t tick_ms() noexcept;
};

} // namespace swm::internal
