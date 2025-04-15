#include "Config.hpp"

#include <glaze/glaze.hpp>

#include "../helpers/FsUtils.hpp"
#include "../GlobalState.hpp"

#include "../debug/log.hpp"

static CConfig::eConfigIPAction strToAction(const std::string& s) {
    // TODO: allow any case I'm lazy it's 1am
    if (s == "ALLOW" || s == "allow" || s == "Allow")
        return CConfig::IP_ACTION_ALLOW;
    if (s == "Deny" || s == "deny" || s == "Deny")
        return CConfig::IP_ACTION_DENY;
    if (s == "CHALLENGE" || s == "challenge" || s == "Challenge")
        return CConfig::IP_ACTION_CHALLENGE;

    throw std::runtime_error("Invalid ip config action");
}

CConfig::CConfig() {
    auto json = glz::read_jsonc<SConfig>(
        NFsUtils::readFileAsString(NFsUtils::isAbsolute(g_pGlobalState->configPath) ? g_pGlobalState->configPath : g_pGlobalState->cwd + "/" + g_pGlobalState->configPath).value());

    if (!json.has_value())
        throw std::runtime_error("No config / bad config format");

    m_config = json.value();

    // parse some datas
    for (const auto& ic : m_config.ip_configs) {
        SIPRangeConfigParsed parsed;
        parsed.action     = strToAction(ic.action);
        parsed.difficulty = ic.difficulty;

        if (!ic.exclude_regex.empty()) {
            parsed.exclude_regex = std::make_unique<re2::RE2>(ic.exclude_regex);
            if (parsed.exclude_regex->error_code() != RE2::NoError) {
                Debug::log(CRIT, "Regex \"{}\" failed to parse", ic.exclude_regex);
                throw std::runtime_error("Failed to parse regex");
            }
        }

        for (const auto& ir : ic.ip_ranges) {
            parsed.ip_ranges.emplace_back(CIPRange(ir));
        }

        m_parsedConfigDatas.ip_configs.emplace_back(std::move(parsed));
    }
}