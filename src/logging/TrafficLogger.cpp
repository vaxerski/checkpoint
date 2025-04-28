#include "TrafficLogger.hpp"

#include <sstream>
#include <fmt/format.h>

#include "../config/Config.hpp"
#include "../debug/log.hpp"
#include "../helpers/RequestUtils.hpp"

CTrafficLogger::CTrafficLogger() {
    if (!g_pConfig->m_config.logging.log_traffic)
        return;

    const auto COMMAS = std::count(g_pConfig->m_config.logging.traffic_log_schema.begin(), g_pConfig->m_config.logging.traffic_log_schema.end(), ',');

    // parse the schema
    std::string_view curr;
    size_t           lastPos = 0;
    bool             first   = true;
    auto             advance = [&]() {
        size_t prev = !first ? lastPos + 1 : lastPos;
        lastPos     = g_pConfig->m_config.logging.traffic_log_schema.find(',', prev);

        if (lastPos == std::string::npos)
            curr = std::string_view{g_pConfig->m_config.logging.traffic_log_schema}.substr(prev);
        else
            curr = std::string_view{g_pConfig->m_config.logging.traffic_log_schema}.substr(prev, lastPos - prev);

        first = false;
    };

    for (size_t i = 0; i < COMMAS + 1; ++i) {
        advance();

        if (curr == "ip")
            m_logSchema.emplace_back(TRAFFIC_IP);
        else if (curr == "epoch")
            m_logSchema.emplace_back(TRAFFIC_EPOCH);
        else if (curr == "domain")
            m_logSchema.emplace_back(TRAFFIC_DOMAIN);
        else if (curr == "resource")
            m_logSchema.emplace_back(TRAFFIC_RESOURCE);
        else if (curr == "useragent")
            m_logSchema.emplace_back(TRAFFIC_USERAGENT);
        else if (curr == "action")
            m_logSchema.emplace_back(TRAFFIC_ACTION);

        if (curr == "")
            break;
    }

    m_file.open(g_pConfig->m_config.logging.traffic_log_file, std::ios::app);

    if (!m_file.good())
        Debug::die("TrafficLogger: bad file {}", g_pConfig->m_config.logging.traffic_log_file);
}

CTrafficLogger::~CTrafficLogger() {
    if (m_file.is_open())
        m_file.close();
}

static std::string sanitize(const std::string& s) {
    if (s.empty())
        return s;

    std::string cpy = s;
    size_t      pos = 0;
    while ((pos = cpy.find('"', pos)) != std::string::npos) {
        cpy.replace(pos, 1, "\\\"");
        pos += 2;
    }

    return cpy;
}

static const char* actionToString(eConfigIPAction a) {
    switch (a) {
        case IP_ACTION_CHALLENGE: return "CHALLENGE";
        case IP_ACTION_ALLOW: return "ALLOW";
        case IP_ACTION_DENY: return "DENY";
        case IP_ACTION_NONE: return "NONE";
    }

    return "ERROR";
}

void CTrafficLogger::logTraffic(const Pistache::Http::Request& req, eConfigIPAction actionTaken) {
    if (!g_pConfig->m_config.logging.log_traffic)
        return;

    std::stringstream ss;

    for (const auto& t : m_logSchema) {
        switch (t) {
            case TRAFFIC_EPOCH: {
                ss << fmt::format("{},", std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                break;
            }

            case TRAFFIC_DOMAIN: {
                const auto HOST = Pistache::Http::Header::header_cast<Pistache::Http::Header::Host>(req.headers().get("Host"));
                ss << fmt::format("\"{}\",", sanitize(HOST->host()));
                break;
            }

            case TRAFFIC_IP: {
                ss << fmt::format("{},", NRequestUtils::ipForRequest(req));
                break;
            }

            case TRAFFIC_RESOURCE: {
                ss << fmt::format("\"{}\",", sanitize(req.resource()));
                break;
            }

            case TRAFFIC_USERAGENT: {
                if (!req.headers().has("User-Agent")) {
                    ss << "\"<no data>\",";
                    break;
                }
                const auto UA = Pistache::Http::Header::header_cast<Pistache::Http::Header::UserAgent>(req.headers().get("User-Agent"));
                ss << fmt::format("\"{}\",", sanitize(UA->agent()));
                break;
            }

            case TRAFFIC_ACTION: {
                ss << fmt::format("{},", actionToString(actionTaken));
                break;
            }
        }
    }

    std::string trafficLine = ss.str();
    if (trafficLine.empty())
        return;

    // replace , with \n
    trafficLine.back() = '\n';

    m_file << trafficLine;
    m_file.flush();
}