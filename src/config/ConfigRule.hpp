#pragma once

#include <re2/re2.h>

#include <string>
#include <memory>
#include <optional>

#include "ConfigTypes.hpp"
#include "IPRange.hpp"

class CConfigRule {
  public:
    eConfigIPAction    action = IP_ACTION_DENY;

    std::optional<int> difficulty;

    bool               passes(const CIP& ip, const std::string& ua, const std::string& res) const;

  private:
    std::vector<CIPRange>                    ip_ranges;
    std::optional<std::unique_ptr<re2::RE2>> user_agent;
    std::optional<std::unique_ptr<re2::RE2>> resource;

    friend class CConfig;
};