#include "IPRange.hpp"

#include <algorithm>
#include <stdexcept>

CIP::CIP(const std::string& ip) {
    if (std::count(ip.begin(), ip.end(), '.') == 3)
        parseV4(ip);
    else if (std::count(ip.begin(), ip.end(), ':') >= 2)
        parseV6(ip);
    else
        throw std::runtime_error("IP not valid");
}

void CIP::parseV4(const std::string& ip) {
    m_v6 = false;

    std::string_view curr;
    size_t           lastPos = 0;
    auto             advance = [&]() {
        size_t prev = lastPos ? lastPos + 1 : lastPos;
        lastPos     = ip.find('.', prev);

        if (lastPos == std::string::npos)
            curr = std::string_view{ip}.substr(prev);
        else
            curr = std::string_view{ip}.substr(prev, lastPos - prev);
    };

    for (size_t i = 0; i < 4; ++i) {
        advance();
        m_blocks.push_back(std::stoul(std::string{curr}));

        if (m_blocks.back() > 0xFF)
            throw std::runtime_error("Invalid IPv4 byte");
    }
}

void CIP::parseV6(const std::string& ip) {
    const auto COLONS = std::count(ip.begin(), ip.end(), ':');

    m_v6 = true;

    std::string_view curr;
    size_t           lastPos = 0;
    bool             first   = true;
    auto             advance = [&]() {
        size_t prev = !first ? lastPos + 1 : lastPos;
        lastPos     = ip.find(':', prev);

        if (lastPos == std::string::npos)
            curr = std::string_view{ip}.substr(prev);
        else
            curr = std::string_view{ip}.substr(prev, lastPos - prev);

        first = false;
    };

    for (size_t i = 0; i < 8; ++i) {
        advance();
        if (curr.empty()) {
            for (size_t j = 0; j < 8 - COLONS; ++j) {
                i++;
                m_blocks.push_back(0);
            }

            if (ip.starts_with("::") || ip.ends_with("::")) {
                m_blocks.push_back(0);
                advance();
            } else
                i--;
            continue;
        } else
            m_blocks.push_back(std::stoul(std::string{curr}, nullptr, 16));

        if (m_blocks.back() > 0xFFFF)
            throw std::runtime_error("Invalid IPv6 byte");
    }
}

CIPRange::CIPRange(const std::string& range) {
    if (!range.contains('/'))
        throw std::runtime_error("Range has no subnet");

    m_subnet = std::stoul(range.substr(range.find('/') + 1));

    m_ip = CIP(range.substr(0, range.find('/')));
}

bool CIPRange::ipMatches(const CIP& ip) const {
    if (m_ip.m_v6 != ip.m_v6)
        return false;

    if (m_ip.m_v6)
        return ipMatchesV6(ip);
    return ipMatchesV4(ip);
}

bool CIPRange::ipMatchesV4(const CIP& ip) const {
    uint32_t rangeMask = 0xFFFFFFFF << (32 - m_subnet);
    uint32_t rangeIP =
        (((uint32_t)m_ip.m_blocks.at(0)) << 24) | (((uint32_t)m_ip.m_blocks.at(1)) << 16) | (((uint32_t)m_ip.m_blocks.at(2)) << 8) | (((uint32_t)m_ip.m_blocks.at(3)) << 0);
    uint32_t incomingIP =
        (((uint32_t)ip.m_blocks.at(0)) << 24) | (((uint32_t)ip.m_blocks.at(1)) << 16) | (((uint32_t)ip.m_blocks.at(2)) << 8) | (((uint32_t)ip.m_blocks.at(3)) << 0);

    return (rangeMask & rangeIP) == (rangeMask & incomingIP);
}

bool CIPRange::ipMatchesV6(const CIP& ip) const {
    uint64_t rangeMaskLeft = 0xFFFFFFFFFFFFFFFF << (m_subnet > 64 ? 0 : 64 - m_subnet);
    uint64_t rangeIPLeft =
        (((uint64_t)m_ip.m_blocks.at(0)) << 48) | (((uint64_t)m_ip.m_blocks.at(1)) << 32) | (((uint64_t)m_ip.m_blocks.at(2)) << 16) | (((uint64_t)m_ip.m_blocks.at(3)) << 0);
    uint64_t incomingIPLeft =
        (((uint64_t)ip.m_blocks.at(0)) << 48) | (((uint64_t)ip.m_blocks.at(1)) << 32) | (((uint64_t)ip.m_blocks.at(2)) << 16) | (((uint64_t)ip.m_blocks.at(3)) << 0);

    if ((rangeMaskLeft & rangeIPLeft) != (rangeMaskLeft & incomingIPLeft))
        return false;

    if (m_subnet <= 64)
        return true;

    uint64_t rangeMaskRight = 0xFFFFFFFFFFFFFFFF << (/* m_subnet > 64 */ 128 - m_subnet);
    uint64_t rangeIPRight =
        (((uint64_t)m_ip.m_blocks.at(4)) << 48) | (((uint64_t)m_ip.m_blocks.at(5)) << 32) | (((uint64_t)m_ip.m_blocks.at(6)) << 16) | (((uint64_t)m_ip.m_blocks.at(7)) << 0);
    uint64_t incomingIPRight =
        (((uint64_t)ip.m_blocks.at(4)) << 48) | (((uint64_t)ip.m_blocks.at(5)) << 32) | (((uint64_t)ip.m_blocks.at(6)) << 16) | (((uint64_t)ip.m_blocks.at(7)) << 0);

    return (rangeMaskRight & rangeIPRight) == (rangeMaskRight & incomingIPRight);
}