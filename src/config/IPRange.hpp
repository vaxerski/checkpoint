#pragma once

#include <string>
#include <vector>
#include <cstdint>

class CIP {
  public:
    CIP() = default;
    CIP(const std::string& ip);

    bool                  m_v6 = false;
    std::vector<uint16_t> m_blocks;

  private:
    void parseV4(const std::string& ip);
    void parseV6(const std::string& ip);
};

// Accepts both ipv4 and ipv6
class CIPRange {
  public:
    CIPRange(const std::string& range);

    bool ipMatches(const CIP& ip) const;

  private:
    CIP    m_ip;
    size_t m_subnet = 0;

    bool   ipMatchesV6(const CIP& ip) const;
    bool   ipMatchesV4(const CIP& ip) const;
};