#pragma once
#include <string>
#include <fmt/format.h>
#include <iostream>
#include "../config/Config.hpp"

enum LogLevel {
    NONE = -1,
    LOG  = 0,
    WARN,
    ERR,
    CRIT,
    INFO,
    TRACE
};

namespace Debug {
    template <typename... Args>
    void log(LogLevel level, fmt::format_string<Args...> fmt, Args&&... args) {

        std::string logMsg = "";

        if (g_pConfig && !g_pConfig->m_config.trace_logging && level == TRACE)
            return;

        switch (level) {
            case LOG: logMsg += "[LOG] "; break;
            case WARN: logMsg += "[WARN] "; break;
            case ERR: logMsg += "[ERR] "; break;
            case CRIT: logMsg += "[CRITICAL] "; break;
            case INFO: logMsg += "[INFO] "; break;
            case TRACE: logMsg += "[TRACE] "; break;
            default: break;
        }

        logMsg += fmt::vformat(fmt.get(), fmt::make_format_args(args...));

        std::cout << logMsg << "\n";
    }

    template <typename... Args>
    void die(fmt::format_string<Args...> fmt, Args&&... args) {
        const std::string logMsg = fmt::vformat(fmt.get(), fmt::make_format_args(args...));

        std::cout << "[ERR] " << logMsg << "\n";
        exit(1);
    }
};
