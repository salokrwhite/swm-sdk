#pragma once

#include "internal/common.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace swm::internal {

class StateStore final {
public:
    StateStore(std::string app_id, std::filesystem::path override_directory = {});

    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return directory_; }
    [[nodiscard]] std::filesystem::path path(std::string_view name) const;

    std::optional<Bytes> read_protected(std::string_view name) const;
    void write_protected(std::string_view name, std::span<const std::uint8_t> plaintext) const;
    void erase(std::string_view name) const;

private:
    std::string app_id_;
    std::filesystem::path directory_;
    Bytes entropy_;
};

} // namespace swm::internal
