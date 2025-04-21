#include "Config.hpp"

#include <glaze/glaze.hpp>

#include "../helpers/FsUtils.hpp"
#include "../GlobalState.hpp"

#include "../debug/log.hpp"

static eConfigIPAction strToAction(const std::string& s) {
    if (s.empty())
        return IP_ACTION_NONE;

    std::string LC = s;
    std::transform(LC.begin(), LC.end(), LC.begin(), ::tolower);

    if (LC == "allow")
        return IP_ACTION_ALLOW;
    if (LC == "deny")
        return IP_ACTION_DENY;
    if (LC == "challenge")
        return IP_ACTION_CHALLENGE;

    Debug::log(ERR, "Invalid action: {}, assuming NONE", s);
    return IP_ACTION_NONE;
}

CConfig::CConfig() {
    auto json = glz::read_jsonc<SConfig>(
        NFsUtils::readFileAsString(NFsUtils::isAbsolute(g_pGlobalState->configPath) ? g_pGlobalState->configPath : g_pGlobalState->cwd + "/" + g_pGlobalState->configPath).value());

    if (!json.has_value())
        Debug::die("No config or config has bad format");

    m_config = json.value();

    // parse some datas
    for (const auto& ic : m_config.rules) {
        CConfigRule rule;
        rule.action = strToAction(ic.action);
        
        if (ic.difficulty != -1)
            rule.difficulty = ic.difficulty;

        if (!ic.user_agent.empty()) {
            rule.user_agent = std::make_unique<re2::RE2>(ic.user_agent);
            if ((*rule.user_agent)->error_code() != RE2::NoError) {
                Debug::log(CRIT, "Regex \"{}\" failed to parse", ic.user_agent);
                Debug::die("Failed to parse regex");
            }
        }

        if (!ic.resource.empty()) {
            rule.resource = std::make_unique<re2::RE2>(ic.resource);
            if ((*rule.resource)->error_code() != RE2::NoError) {
                Debug::log(CRIT, "Regex \"{}\" failed to parse", ic.resource);
                Debug::die("Failed to parse regex");
            }
        }

        for (const auto& ir : ic.ip_ranges) {
            rule.ip_ranges.emplace_back(CIPRange(ir));
        }

        m_parsedConfigDatas.configs.emplace_back(std::move(rule));
    }
}