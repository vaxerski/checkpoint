#pragma once

#include <cstdint>

enum eConfigIPAction : uint8_t {
    IP_ACTION_NONE = 0,
    IP_ACTION_DENY,
    IP_ACTION_ALLOW,
    IP_ACTION_CHALLENGE
};