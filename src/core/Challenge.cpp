#include "Challenge.hpp"

#include "Crypto.hpp"

#include <fmt/format.h>
#include <glaze/glaze.hpp>

constexpr const uint64_t CHALLENGE_VERSION       = 2;
constexpr const uint64_t CHALLENGE_EXPIRE_TIME_S = 600; // 10 minutes

CChallenge::CChallenge(const std::string& fingerprint, const std::string& challenge, int difficulty) :
    m_fingerprint(fingerprint), m_challenge(challenge), m_difficulty(difficulty), m_issued(std::chrono::system_clock::now()) {
    std::string toSign = getSigString();

    m_sig = g_pCrypto->sign(toSign);

    m_valid = true;
}

CChallenge::CChallenge(const std::string& jsonResponse) {
    auto json = glz::read_json<SChallengeJSON>(jsonResponse);

    if (!json.has_value())
        return;

    SChallengeJSON s = json.value();

    m_challenge   = s.challenge;
    m_fingerprint = s.fingerprint;
    m_sig         = s.sig;

    try {
        m_issued = std::chrono::system_clock::time_point(std::chrono::seconds(std::stoull(s.timestamp)));
    } catch (std::exception& e) { return; }

    if (!g_pCrypto->verifySignature(getSigString(), m_sig))
        return;

    const auto SHA = g_pCrypto->sha256(m_challenge + std::to_string(s.solution));

    for (size_t i = 0; i < m_difficulty; ++i) {
        if (SHA.at(i) != '0')
            return;
    }

    m_valid = true;
}

CChallenge::CChallenge(const Pistache::Http::Request& reqResponse) {
    auto& q = reqResponse.query();

    if (!q.has("solution")
        || !q.has("fingerprint")
        || !q.has("challenge")
        || !q.has("timestamp")
        || !q.has("sig")
        || !q.has("difficulty"))
        return;

    m_challenge = q.get("challenge").value();
    m_fingerprint = q.get("fingerprint").value();
    m_sig = q.get("sig").value();

    try {
        m_issued = std::chrono::system_clock::time_point(std::chrono::seconds(std::stoull(q.get("timestamp").value())));
    } catch (std::exception& e) { return; }

    if (!g_pCrypto->verifySignature(getSigString(), m_sig))
        return;

    const auto SHA = g_pCrypto->sha256(m_challenge + q.get("solution").value());

    for (size_t i = 0; i < m_difficulty; ++i) {
        if (SHA.at(i) != '0')
            return;
    }

    m_valid = true;
}

std::string CChallenge::fingerprint() const {
    return m_fingerprint;
}

std::string CChallenge::challenge() const {
    return m_challenge;
}

std::string CChallenge::signature() const {
    return m_sig;
}

bool CChallenge::valid() const {
    return m_valid && std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - m_issued).count() < CHALLENGE_EXPIRE_TIME_S;
}

std::string CChallenge::getSigString() {
    return fmt::format("{}-{},{},{}", CHALLENGE_VERSION, m_fingerprint, m_challenge, std::chrono::duration_cast<std::chrono::seconds>(m_issued.time_since_epoch()).count());
}

std::string CChallenge::timestampAsString() const {
    return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(m_issued.time_since_epoch()).count());
}
