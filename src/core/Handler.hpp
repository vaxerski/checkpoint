#pragma once

#include <pistache/http.h>

class CServerHandler : public Pistache::Http::Handler {

    HTTP_PROTOTYPE(CServerHandler)

    void onRequest(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response);

    void onTimeout(const Pistache::Http::Request& request, Pistache::Http::ResponseWriter response);

  private:
    void serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    void proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    void challengeSubmitted(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);

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