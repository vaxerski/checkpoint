#pragma once

#include <string>

class CChallenge {
  public:
    CChallenge(const std::string& fingerprint, const std::string& challenge, int difficulty);
    CChallenge(const std::string& jsonResponse);

    std::string fingerprint() const;
    std::string challenge() const;
    std::string signature() const;
    bool        valid() const;

  private:
    std::string getSigString();

    std::string m_sig, m_fingerprint, m_challenge;
    bool        m_valid      = false;
    int         m_difficulty = 4;

    struct SChallengeJSON {
        std::string fingerprint, challenge, sig;
        int         difficulty = 4, solution = 0;
    };
};