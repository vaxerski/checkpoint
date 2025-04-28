#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <fstream>

#include "../config/ConfigTypes.hpp"

#include <pistache/http.h>

class CTrafficLogger {
  public:
    CTrafficLogger();
    ~CTrafficLogger();

    void logTraffic(const Pistache::Http::Request& req, const char* actionTaken);

  private:
    enum eTrafficLoggerProps : uint8_t {
        TRAFFIC_EPOCH = 0,
        TRAFFIC_IP,
        TRAFFIC_DOMAIN,
        TRAFFIC_RESOURCE,
        TRAFFIC_USERAGENT,
        TRAFFIC_ACTION,
    };

    std::vector<eTrafficLoggerProps> m_logSchema;
    std::ofstream                    m_file;
};

inline std::unique_ptr<CTrafficLogger> g_pTrafficLogger;