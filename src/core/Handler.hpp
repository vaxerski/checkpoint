#pragma once

#include <pistache/http.h>
#include <mutex>

// Giga hack, but we need it cuz the API is quite awkward and incomplete
#define private public
#include <pistache/client.h>
#undef private

class CServerHandler : public Pistache::Http::Handler {

    HTTP_PROTOTYPE(CServerHandler)

    void onRequest(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response);

    void onTimeout(const Pistache::Http::Request& request, Pistache::Http::ResponseWriter response);

  private:
    void serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, int difficulty);
    void proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    void proxyPassInternal(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, bool async = false);
    void proxyPassAsync(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response);
    void challengeSubmitted(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, bool js);

    bool isResourceCheckpoint(const std::string_view& res);

    struct SChallengeResponse {
        std::string       challenge;
        unsigned long int solution = 0;
    };

    struct STokenResponse {
        bool        success = false;
        std::string token   = "";
        std::string error   = "";
    };

    struct SProxiedRequest {
        SProxiedRequest(const Pistache::Http::Request& r, Pistache::Http::ResponseWriter& resp) : req(r), response(std::move(resp)) {
            ;
        }

        Pistache::Http::Request        req;
        Pistache::Http::ResponseWriter response;
        std::thread                    requestThread;
    };

    struct {
        std::vector<std::shared_ptr<SProxiedRequest>> queue;
        std::shared_ptr<std::mutex>                   queueMutex = std::make_shared<std::mutex>();
    } m_asyncProxyQueue;
};