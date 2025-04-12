#pragma once

#include <sqlite3.h>
#include <string>
#include <chrono>
#include <optional>
#include <memory>

struct SDatabaseChallengeEntry {
    std::string       nonce      = "";
    int               difficulty = 0;
    unsigned long int epoch      = std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1);
    std::string       ip         = "";
};

struct SDatabaseTokenEntry {
    std::string       token = "";
    unsigned long int epoch = std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1);
    std::string       ip    = "";
};

class CDatabase {
  public:
    CDatabase();
    ~CDatabase();

    void                                   addChallenge(const SDatabaseChallengeEntry& entry);
    std::optional<SDatabaseChallengeEntry> getChallenge(const std::string& nonce);
    void                                   dropChallenge(const std::string& nonce);

    void                                   addToken(const SDatabaseTokenEntry& entry);
    std::optional<SDatabaseTokenEntry>     getToken(const std::string& token);
    void                                   dropToken(const std::string& token);

  private:
    struct SQueryResult {
        bool                     failed = false;
        std::string              error  = "";
        std::vector<std::string> result;
        std::vector<std::string> result2;
    };

    sqlite3*                              m_db            = nullptr;
    std::chrono::steady_clock::time_point m_lastDbCleanup = std::chrono::steady_clock::now();

    void                                  cleanupDb();
    bool                                  shouldCleanupDb();
};

inline std::unique_ptr<CDatabase> g_pDB;