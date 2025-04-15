#pragma once

#include <pistache/http.h>

// Giga hack, but we need it cuz the API is quite awkward and incomplete
#define private public
#include <pistache/client.h>
#undef private

class CServerHandler : public Pistache::Http::Handler {

    HTTP_PROTOTYPE(CServerHandler)

    void onRequest(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response);

    void onTimeout(const Pistache::Http::Request& request, Pistache::Http::ResponseWriter response);

  private:
    void        serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, int difficulty);
    void        proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    void        challengeSubmitted(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    std::string fingerprintForRequest(const Pistache::Http::Request& req);
    std::string ipForRequest(const Pistache::Http::Request& req);

    bool        isResourceCheckpoint(const std::string_view& res);

    struct SChallengeResponse {
        std::string       challenge;
        unsigned long int solution = 0;
    };

    struct STokenResponse {
        bool        success = false;
        std::string token   = "";
        std::string error   = "";
    };
};