#include "Config.hpp"

#include <glaze/glaze.hpp>

#include "../GlobalState.hpp"

static std::string readFileAsText(const std::string& path) {
    std::ifstream ifs(path);
    auto          res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    if (res.back() == '\n')
        res.pop_back();
    return res;
}

CConfig::CConfig() {
    auto json = glz::read_jsonc<SConfig>(readFileAsText(g_pGlobalState->cwd + "/" + g_pGlobalState->configPath));

    if (!json.has_value())
        throw std::runtime_error("No config / bad config format");

    m_config = json.value();
}