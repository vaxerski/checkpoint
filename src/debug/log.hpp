#pragma once
#include <string>
#include <fmt/format.h>
#include <iostream>

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
};
