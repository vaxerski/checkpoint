#pragma once

#include <string>
#include <expected>

namespace NFsUtils {
    bool                                    isAbsolute(const std::string& path);
    std::expected<std::string, std::string> readFileAsString(const std::string& path);
    std::string                             htmlPath(const std::string& resource);
    std::string                             dataDir();
};