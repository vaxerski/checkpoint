#include "Challenge.hpp"

#include "Crypto.hpp"

#include <fmt/format.h>
#include <glaze/glaze.hpp>

constexpr const uint64_t CHALLENGE_VERSION = 1;

CChallenge::CChallenge(const std::string& fingerprint, const std::string& challenge, int difficulty) :
    m_fingerprint(fingerprint), m_challenge(challenge), m_difficulty(difficulty) {
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

    if (!g_pCrypto->verifySignature(getSigString(), m_sig))
        return;

    const auto SHA = g_pCrypto->sha256(m_challenge + std::to_string(s.solution));

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
    return m_valid;
}

std::string CChallenge::getSigString() {
    return fmt::format("{}-{},{}", CHALLENGE_VERSION, m_fingerprint, m_challenge);
}
