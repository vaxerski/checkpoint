#pragma once

#include <string>

#include <pistache/http.h>

namespace NRequestUtils {
    std::string fingerprintForRequest(const Pistache::Http::Request& req);
    std::string ipForRequest(const Pistache::Http::Request& req);
};