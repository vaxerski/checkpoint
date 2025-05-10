#pragma once

#include <string>
#include <memory>

#include <re2/re2.h>

#include "ConfigRule.hpp"

class CConfig {
  public:
    CConfig();

    struct SConfigRule {
        std::string              action     = "";
        int                      difficulty = -1;
        std::vector<std::string> ip_ranges  = {};
        std::string              user_agent = "";
        std::string              resource   = "";
    };

    struct SProxyRule {
        std::string host        = "";
        std::string destination = "";
    };

    struct SConfig {
        int                      port                         = 3001;
        std::string              forward_address              = "127.0.0.1:3000";
        std::string              data_dir                     = "";
        std::string              html_dir                     = "";
        unsigned long int        max_request_size             = 10000000; // 10MB
        bool                     git_host                     = false;
        unsigned long int        proxy_timeout_sec            = 120; // 2 minutes
        bool                     trace_logging                = false;
        std::vector<SConfigRule> rules                        = {};
        int                      default_challenge_difficulty = 4;
        int                      token_valid_for              = 60;
        bool                     async_proxy                  = true;
        std::vector<SProxyRule>  proxy_rules;

        struct {
            bool        log_traffic = false;
            std::string traffic_log_schema;
            std::string traffic_log_file;
        } logging;
    } m_config;

    struct {
        std::vector<CConfigRule> configs;
    } m_parsedConfigDatas;
};

inline std::unique_ptr<CConfig> g_pConfig;