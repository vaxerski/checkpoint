#pragma once

#include <string>
#include <memory>

#include "IPRange.hpp"

class CConfig {
  public:
    CConfig();

    enum eConfigIPAction : uint8_t {
        IP_ACTION_DENY = 0,
        IP_ACTION_ALLOW,
        IP_ACTION_CHALLENGE
    };

    struct SIPRangeConfig {
        std::string              action = "";
        std::vector<std::string> ip_ranges;
        int                      difficulty = -1;
    };

    struct SIPRangeConfigParsed {
        eConfigIPAction       action = IP_ACTION_DENY;
        std::vector<CIPRange> ip_ranges;
        int                   difficulty = -1;
    };

    struct SConfig {
        int                         port              = 3001;
        std::string                 forward_address   = "127.0.0.1:3000";
        std::string                 data_dir          = "";
        std::string                 html_dir          = "";
        unsigned long int           max_request_size  = 10000000; // 10MB
        bool                        git_host          = false;
        unsigned long int           proxy_timeout_sec = 120; // 2 minutes
        bool                        trace_logging     = false;
        std::vector<SIPRangeConfig> ip_configs;
        int                         default_challenge_difficulty = 4;
    } m_config;

    struct {
        std::vector<SIPRangeConfigParsed> ip_configs;
    } m_parsedConfigDatas;
};

inline std::unique_ptr<CConfig> g_pConfig;