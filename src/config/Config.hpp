#pragma once

#include <string>
#include <memory>

class CConfig {
  public:
    CConfig();

    struct SConfig {
        int               port             = 3001;
        std::string       forward_address  = "127.0.0.1:3000";
        std::string       data_dir         = "";
        std::string       html_dir         = "";
        unsigned long int max_request_size = 10000000; // 10MB
    } m_config;
};

inline std::unique_ptr<CConfig> g_pConfig;