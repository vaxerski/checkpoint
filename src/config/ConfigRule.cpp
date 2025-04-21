#include "ConfigRule.hpp"

bool CConfigRule::passes(const CIP& ip, const std::string& ua, const std::string& res) const {
    if (!ip_ranges.empty()) {
        bool passed = false;
        for (const auto& r : ip_ranges) {
            if (r.ipMatches(ip)) {
                passed = true;
                break;
            }
        }

        if (!passed)
            return false;
    }

    if (user_agent.has_value()) {
        if (!RE2::FullMatch(ua, **user_agent))
            return false;
    }

    if (resource.has_value()) {
        if (!RE2::FullMatch(res, **resource))
            return false;
    }

    return true;
}