#include "Config.hpp"

#include <glaze/glaze.hpp>
#include <filesystem>
#include <string>
#include <stdexcept>
#include <fstream>
#include <fstream>


#include "../GlobalState.hpp"

// TODO: should probably be in a commons file or whatever
static std::string readFileAsText(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) {
        throw std::runtime_error("Could not open file: " + path);
    }

    auto res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    if (!res.empty() && res.back() == '\n') {
        res.pop_back();
    }

    return res;
}

CConfig::CConfig() {
    std::string user_config_path_str = g_pGlobalState->configPath;

    std::filesystem::path user_config_path = user_config_path_str;

    std::filesystem::path final_config_path;
    if (user_config_path.is_absolute()) {
        final_config_path = user_config_path;
    } else {

        final_config_path = std::filesystem::path(g_pGlobalState->cwd) / user_config_path;
    }

    std::error_code ec;
    final_config_path = std::filesystem::canonical(final_config_path, ec);
    if (ec) {
       throw std::runtime_error("Error resolving config path: " + final_config_path.string() + " - " + ec.message());
    }

    std::string config_content;
    try {
        config_content = readFileAsText(final_config_path.string());
    } catch (const std::runtime_error& e) {
        throw std::runtime_error("Failed to read configuration file '" + final_config_path.string() + "': " + e.what());
    }

    auto json = glz::read_jsonc<SConfig>(config_content);

    if (!json.has_value()) {
        throw std::runtime_error("No config / bad config format in file: " + final_config_path.string());
    }

    m_config = json.value();
}