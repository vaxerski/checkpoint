#include "Token.hpp"

#include "Crypto.hpp"

#include <fmt/format.h>

constexpr const uint64_t TOKEN_VERSION = 1;

CToken::CToken(const std::string& fingerprint, std::chrono::system_clock::time_point issued) : m_fingerprint(fingerprint), m_issued(issued) {
    std::string toSign = getSigString();

    m_sig = g_pCrypto->sign(toSign);

    m_fullCookie = fmt::format("{},{}", toSign, m_sig);

    m_valid = true;
}

CToken::CToken(const std::string& cookie) : m_fullCookie(cookie) {
    // try to parse the cookie
    if (std::count(cookie.begin(), cookie.end(), ',') != 2)
        return;

    if (!cookie.contains('-'))
        return;

    auto dash = cookie.find('-');

    try {
        if (std::stoi(cookie.substr(0, dash)) != TOKEN_VERSION)
            return;
    } catch (std::exception& e) { return; }

    std::string_view cookieData = std::string_view{cookie}.substr(dash + 1);
    auto             firstComma = cookieData.find(',');
    auto             lastComma  = cookieData.find_last_of(',');

    m_fingerprint      = cookieData.substr(0, firstComma);
    m_sig              = cookieData.substr(lastComma + 1);
    const auto tpStrMs = cookieData.substr(firstComma + 1, lastComma - firstComma - 1);

    try {
        m_issued = std::chrono::system_clock::time_point(std::chrono::milliseconds(std::stoull(std::string{tpStrMs})));
    } catch (std::exception& e) { return; }

    std::string toSign = getSigString();

    m_valid = g_pCrypto->verifySignature(toSign, m_sig);
}

std::string CToken::tokenCookie() const {
    return m_fullCookie;
}

std::string CToken::fingerprint() const {
    return m_fingerprint;
}

bool CToken::valid() const {
    return m_valid;
}

std::chrono::system_clock::time_point CToken::issued() const {
    return m_issued;
}

std::string CToken::getSigString() {
    return fmt::format("{}-{},{}", TOKEN_VERSION, m_fingerprint, std::chrono::duration_cast<std::chrono::milliseconds>(m_issued.time_since_epoch()).count());
}
