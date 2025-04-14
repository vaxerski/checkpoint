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
    if (!ifs)
        throw std::runtime_error("Could not open file: " + path);

    auto res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    if (!res.empty() && res.back() == '\n')
        res.pop_back();


    return res;
}

CConfig::CConfig() {
    std::string userConfigPathStr = g_pGlobalState->configPath;

    std::filesystem::path userConfigPath = userConfigPathStr;

    std::filesystem::path finalConfigPath;
    if (userConfigPath.is_absolute())
        finalConfigPath = userConfigPath;
    else
        finalConfigPath = std::filesystem::path(g_pGlobalState->cwd) / userConfigPath;

    std::error_code ec;
    finalConfigPath = std::filesystem::canonical(finalConfigPath, ec);
    if (ec)
        throw std::runtime_error("Error resolving config path: " + finalConfigPath.string() + " - " + ec.message());


    std::string configContent;
    try {
        configContent = readFileAsText(finalConfigPath.string());
    } catch (const std::runtime_error& e) {
        throw std::runtime_error("Failed to read configuration file '" + finalConfigPath.string() + "': " + e.what());
    }

    auto jsonConfig = glz::read_jsonc<SConfig>(configContent);

    if (!jsonConfig.has_value())
        throw std::runtime_error("No config / bad config format in file: " + finalConfigPath.string());


    m_config = jsonConfig.value();
}