#pragma once

#include <string>
#include <string_view>
#include <chrono>

class CToken {
  public:
    CToken(const std::string& fingerprint, std::chrono::system_clock::time_point issued);
    CToken(const std::string& cookie);

    std::string                           tokenCookie() const;
    std::string                           fingerprint() const;
    bool                                  valid() const;
    std::chrono::system_clock::time_point issued() const;

  private:
    std::string                           getSigString();

    std::string                           m_sig, m_fingerprint, m_fullCookie;
    std::chrono::system_clock::time_point m_issued;
    bool                                  m_valid = false;
};