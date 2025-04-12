#pragma once

#include <string>
#include <memory>

struct SGlobalState {
    std::string cwd;
    std::string configPath;
};

inline std::unique_ptr<SGlobalState> g_pGlobalState = std::make_unique<SGlobalState>();
