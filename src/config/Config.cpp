#include "Config.hpp"

#include <glaze/glaze.hpp>

#include "../helpers/FsUtils.hpp"
#include "../GlobalState.hpp"

CConfig::CConfig() {
    auto json = glz::read_jsonc<SConfig>(
        NFsUtils::readFileAsString(NFsUtils::isAbsolute(g_pGlobalState->configPath) ? g_pGlobalState->configPath : g_pGlobalState->cwd + "/" + g_pGlobalState->configPath).value());

    if (!json.has_value())
        throw std::runtime_error("No config / bad config format");

    m_config = json.value();
}