#include "Handler.hpp"
#include "Crypto.hpp"
#include "Token.hpp"
#include "Challenge.hpp"
#include "../headers/authorization.hpp"
#include "../headers/cfHeader.hpp"
#include "../headers/xforwardfor.hpp"
#include "../headers/gitProtocolHeader.hpp"
#include "../headers/acceptLanguageHeader.hpp"
#include "../headers/setCookieHeader.hpp"
#include "../headers/xrealip.hpp"
#include "../debug/log.hpp"
#include "../GlobalState.hpp"
#include "../config/Config.hpp"
#include "../helpers/FsUtils.hpp"

#include <filesystem>
#include <random>
#include <sstream>

#include <tinylates/tinylates.hpp>
#include <fmt/format.h>
#include <glaze/glaze.hpp>
#include <openssl/evp.h>
#include <magic.h>

constexpr const uint64_t TOKEN_MAX_AGE_MS  = 1000 * 60 * 60; // 1hr
constexpr const char*    TOKEN_COOKIE_NAME = "checkpoint-token";

//

static std::string generateNonce() {
    static std::random_device       dev;
    std::mt19937                    engine(dev());
    std::uniform_int_distribution<> distribution(0, INT32_MAX);

    std::stringstream               ss;
    for (size_t i = 0; i < 32; ++i) {
        ss << fmt::format("{:08x}", distribution(engine));
    }

    return ss.str();
}

static std::string generateToken() {
    static std::random_device       dev;
    std::mt19937                    engine(dev());
    std::uniform_int_distribution<> distribution(0, INT32_MAX);

    std::stringstream               ss;
    for (size_t i = 0; i < 16; ++i) {
        ss << fmt::format("{:08x}", distribution(engine));
    }

    return ss.str();
}

std::string CServerHandler::fingerprintForRequest(const Pistache::Http::Request& req) {
    const auto                                                    HEADERS = req.headers();
    std::shared_ptr<const Pistache::Http::Header::AcceptEncoding> acceptEncodingHeader;
    std::shared_ptr<const Pistache::Http::Header::UserAgent>      userAgentHeader;
    std::shared_ptr<const AcceptLanguageHeader>                   languageHeader;

    std::string                                                   input = "checkpoint-";

    try {
        acceptEncodingHeader = Pistache::Http::Header::header_cast<Pistache::Http::Header::AcceptEncoding>(HEADERS.get("Accept-Encoding"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        languageHeader = Pistache::Http::Header::header_cast<AcceptLanguageHeader>(HEADERS.get("Accept-Language"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        userAgentHeader = Pistache::Http::Header::header_cast<Pistache::Http::Header::UserAgent>(HEADERS.get("User-Agent"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    input += ipForRequest(req);
    // TODO: those seem to change. Find better things to hash.
    // if (acceptEncodingHeader)
    //     input += HEADERS.getRaw("Accept-Encoding").value();
    // if (languageHeader)
    //     input += languageHeader->language();
    if (userAgentHeader)
        input += userAgentHeader->agent();

    return g_pCrypto->sha256(input);
}

bool CServerHandler::isResourceCheckpoint(const std::string_view& res) {
    return res.starts_with("/checkpoint/");
}

std::string CServerHandler::ipForRequest(const Pistache::Http::Request& req) {
    std::shared_ptr<const CFConnectingIPHeader> cfHeader;
    std::shared_ptr<const XRealIPHeader>        xRealIPHeader;

    try {
        cfHeader = Pistache::Http::Header::header_cast<CFConnectingIPHeader>(req.headers().get("cf-connecting-ip"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        xRealIPHeader = Pistache::Http::Header::header_cast<XRealIPHeader>(req.headers().get("X-Real-IP"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    if (cfHeader)
        return cfHeader->ip();

    if (xRealIPHeader)
        return xRealIPHeader->ip();

    return req.address().host();
}

void CServerHandler::onRequest(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response) {
    const auto                                                 HEADERS = req.headers();
    std::shared_ptr<const Pistache::Http::Header::Host>        hostHeader;
    std::shared_ptr<const Pistache::Http::Header::ContentType> contentTypeHeader;
    std::shared_ptr<const Pistache::Http::Header::UserAgent>   userAgentHeader;
    std::shared_ptr<const CFConnectingIPHeader>                cfHeader;
    std::shared_ptr<const XForwardedForHeader>                 xForwardedForHeader;
    std::shared_ptr<const AuthorizationHeader>                 authHeader;
    std::shared_ptr<const GitProtocolHeader>                   gitProtocolHeader;

    try {
        hostHeader = Pistache::Http::Header::header_cast<Pistache::Http::Header::Host>(HEADERS.get("Host"));
    } catch (std::exception& e) {
        Debug::log(ERR, "Request has no Host header?");
        response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
        return;
    }

    try {
        cfHeader = Pistache::Http::Header::header_cast<CFConnectingIPHeader>(HEADERS.get("cf-connecting-ip"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        xForwardedForHeader = Pistache::Http::Header::header_cast<XForwardedForHeader>(HEADERS.get("X-Forwarded-For"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        authHeader = Pistache::Http::Header::header_cast<AuthorizationHeader>(HEADERS.get("Authorization"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        contentTypeHeader = Pistache::Http::Header::header_cast<Pistache::Http::Header::ContentType>(HEADERS.get("Content-Type"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        userAgentHeader = Pistache::Http::Header::header_cast<Pistache::Http::Header::UserAgent>(HEADERS.get("User-Agent"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    try {
        gitProtocolHeader = Pistache::Http::Header::header_cast<GitProtocolHeader>(HEADERS.get("Git-Protocol"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    Debug::log(LOG, "New request: {}:{}{}", hostHeader->host(), hostHeader->port().toString(), req.resource());

    const auto REQUEST_IP = ipForRequest(req);

    Debug::log(LOG, " | Request author: IP {}, direct: {}", REQUEST_IP, req.address().host());

    if (userAgentHeader)
        Debug::log(LOG, " | UA: {}", userAgentHeader->agent());

    if (req.resource() == "/checkpoint/challenge") {
        if (req.method() == Pistache::Http::Method::Post)
            challengeSubmitted(req, response);
        else
            response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
        return;
    }

    if (g_pConfig->m_config.git_host) {
        // TODO: ratelimit this, probably.

        const auto RES        = req.resource();
        bool validGitResource = RES.ends_with("/info/refs") || RES.ends_with("/info/packs") || RES.ends_with("HEAD") || RES.ends_with(".git") || RES.ends_with("/git-upload-pack");

        if (RES.contains("/objects/")) {
            const std::string_view repo = std::string_view{RES}.substr(0, RES.find("/objects/"));
            if (std::count(repo.begin(), repo.end(), '/') == 2)
                validGitResource = true;
        }

        if (validGitResource) {
            if (gitProtocolHeader && userAgentHeader) {
                Debug::log(LOG, " | Action: PASS (git)");
                Debug::log(TRACE, "Request looks like it is coming from git (UA + GP). Accepting.");

                proxyPass(req, response);
                return;
            } else if (userAgentHeader->agent().starts_with("git/")) {
                Debug::log(LOG, " | Action: PASS (git)");
                Debug::log(TRACE, "Request looks like it is coming from git (UA git). Accepting.");

                proxyPass(req, response);
                return;
            }
        }
    }

    int challengeDifficulty = g_pConfig->m_config.default_challenge_difficulty;

    if (!g_pConfig->m_parsedConfigDatas.ip_configs.empty()) {
        const auto IP = CIP(REQUEST_IP);
        for (const auto& ic : g_pConfig->m_parsedConfigDatas.ip_configs) {
            bool matched = false;

            for (const auto& ipr : ic.ip_ranges) {
                if (!ipr.ipMatches(IP))
                    continue;

                matched = true;
                break;
            }

            if (matched) {
                if (ic.difficulty != -1)
                    challengeDifficulty = ic.difficulty;

                // if we have an exclude regex and it matches the resource, skip this rule
                if (ic.exclude_regex && RE2::FullMatch(req.resource(), *ic.exclude_regex)) {
                    if (ic.action_on_exclude == CConfig::IP_ACTION_ALLOW) {
                        Debug::log(LOG, " | Action: PASS (ip rule matched for {}, excluded resource, exclude action is PASS)", REQUEST_IP);
                        proxyPass(req, response);
                        return;
                    } else if (ic.action_on_exclude == CConfig::IP_ACTION_DENY) {
                        Debug::log(LOG, " | Action: DENY (ip rule matched for {}, excluded resource, exclude action is DENY)", REQUEST_IP);
                        response.send(Pistache::Http::Code::Forbidden, "Forbidden");
                        return;
                    } else if (ic.action_on_exclude == CConfig::IP_ACTION_CHALLENGE) {
                        Debug::log(LOG, " | ip rule matched for {}, excluded resource, exclude action is CHALLENGE", REQUEST_IP);
                        break;
                    }
                    Debug::log(LOG, " | ip rule matched for {}, excluded resource, exclude action is NONE", REQUEST_IP);
                    continue;
                }

                if (ic.action == CConfig::IP_ACTION_ALLOW) {
                    Debug::log(LOG, " | Action: PASS (ip rule matched for {})", REQUEST_IP);
                    proxyPass(req, response);
                    return;
                } else if (ic.action == CConfig::IP_ACTION_DENY) {
                    Debug::log(LOG, " | Action: DENY (ip rule matched for {})", REQUEST_IP);
                    response.send(Pistache::Http::Code::Forbidden, "Forbidden");
                    return;
                }

                // if it's challenge then it's default so just set the difficulty if applicable and proceed
                break;
            }
        }
    }

    if (req.cookies().has(TOKEN_COOKIE_NAME)) {
        // check the token
        const auto TOKEN = CToken(req.cookies().get(TOKEN_COOKIE_NAME).value);
        if (TOKEN.valid()) {
            const auto AGE = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() -
                std::chrono::duration_cast<std::chrono::milliseconds>(TOKEN.issued().time_since_epoch()).count();
            if (AGE <= TOKEN_MAX_AGE_MS && TOKEN.fingerprint() == fingerprintForRequest(req)) {
                Debug::log(LOG, " | Action: PASS (token)");
                proxyPass(req, response);
                return;
            } else { // token has been used from a different IP or is expired. Nuke it.
                if (AGE > TOKEN_MAX_AGE_MS)
                    Debug::log(LOG, " | Action: CHALLENGE (token expired)");
                else
                    Debug::log(LOG, " | Action: CHALLENGE (token fingerprint mismatch)");
            }
        } else
            Debug::log(LOG, " | Action: CHALLENGE (token invalid)");
    } else
        Debug::log(LOG, " | Action: CHALLENGE (no token)");

    if (isResourceCheckpoint(req.resource())) {
        static const auto HTML_ROOT = std::filesystem::canonical(NFsUtils::htmlPath("")).string();

        const auto        RESOURCE_PATH = req.resource().substr(req.resource().find("checkpoint/") + 11);
        const auto        PATH_RAW      = NFsUtils::htmlPath(RESOURCE_PATH);

        std::error_code   ec;
        const auto        PATH_ABSOLUTE = std::filesystem::canonical(PATH_RAW, ec);

        if (ec) {
            // bad resource
            response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
            return;
        }

        if (!PATH_ABSOLUTE.string().starts_with(HTML_ROOT)) {
            // directory traversal
            response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
            return;
        }

        // attempt to handle mime
        magic_t magic = magic_open(MAGIC_MIME_TYPE);
        if (magic && magic_load(magic, nullptr) == 0) {
            const char* m        = magic_file(magic, PATH_ABSOLUTE.c_str());
            auto        mimeType = Pistache::Http::Mime::MediaType::fromString(m ? std::string(m) : std::string("application/octet-stream"));
            response.headers().add<Pistache::Http::Header::ContentType>(mimeType);
        }
        if (magic)
            magic_close(magic);

        auto body = NFsUtils::readFileAsString(PATH_ABSOLUTE).value_or("");
        response.send(body.empty() ? Pistache::Http::Code::Internal_Server_Error : Pistache::Http::Code::Ok, body);
        return;
    }

    serveStop(req, response, challengeDifficulty);
}

void CServerHandler::onTimeout(const Pistache::Http::Request& request, Pistache::Http::ResponseWriter response) {
    response.send(Pistache::Http::Code::Request_Timeout, "Timeout").then([=](ssize_t) {}, PrintException());
}

void CServerHandler::challengeSubmitted(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    const auto JSON        = req.body();
    const auto FINGERPRINT = fingerprintForRequest(req);

    const auto CHALLENGE = CChallenge(req.body());

    if (!CHALLENGE.valid()) {
        response.send(Pistache::Http::Code::Bad_Request, "Bad request");
        return;
    }

    // correct solution, return a token

    const auto TOKEN = CToken(FINGERPRINT, std::chrono::system_clock::now());

    auto       hostDomain = req.headers().getRaw("Host").value();
    if (hostDomain.contains(":"))
        hostDomain = hostDomain.substr(0, hostDomain.find(':'));

    // ipv4 vvvvvvvv                                vvvv ipv6
    if (!std::isdigit(hostDomain.back()) && hostDomain.back() != ']') {
        size_t lastdot = hostDomain.find_last_of('.');
        lastdot        = hostDomain.find_last_of('.', lastdot - 1);
        if (lastdot != std::string::npos)
            hostDomain = hostDomain.substr(lastdot + 1);
    }

    response.headers().add(
        std::make_shared<SetCookieHeader>(std::string{TOKEN_COOKIE_NAME} + "=" + TOKEN.tokenCookie() + "; Domain=" + hostDomain + "; HttpOnly; Path=/; Secure; SameSite=Lax"));

    response.send(Pistache::Http::Code::Ok, "Ok");
}

void CServerHandler::serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, int difficulty) {
    static const auto PAGE_INDEX = NFsUtils::readFileAsString(NFsUtils::htmlPath("/index.min.html")).value();
    static const auto PAGE_ROOT  = PAGE_INDEX.substr(0, PAGE_INDEX.find_last_of("/") + 1);
    CTinylates        page(PAGE_INDEX);
    page.setTemplateRoot(PAGE_ROOT);

    const auto NONCE     = generateNonce();
    const auto CHALLENGE = CChallenge(fingerprintForRequest(req), NONCE, difficulty);

    page.add("challengeDifficulty", CTinylatesProp(std::to_string(difficulty)));
    page.add("challengeNonce", CTinylatesProp(NONCE));
    page.add("challengeSignature", CTinylatesProp(CHALLENGE.signature()));
    page.add("challengeFingerprint", CTinylatesProp(CHALLENGE.fingerprint()));
    page.add("challengeTimestamp", CTinylatesProp(CHALLENGE.timestampAsString()));
    page.add("checkpointVersion", CTinylatesProp(CHECKPOINT_VERSION));
    response.send(Pistache::Http::Code::Ok, page.render().value_or("error"));
}

void CServerHandler::proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    if (g_pConfig->m_config.async_proxy) {
        proxyPassAsync(req, response);
        return;
    }

    proxyPassInternal(req, response);
}

void CServerHandler::proxyPassAsync(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    std::shared_ptr<SProxiedRequest> proxiedRequest;
    {
        std::lock_guard<std::mutex> lg(*m_asyncProxyQueue.queueMutex);
        proxiedRequest = m_asyncProxyQueue.queue.emplace_back(std::make_shared<SProxiedRequest>(req, response));
        Debug::log(TRACE, "proxyPassAsync: new request, queue size {}", m_asyncProxyQueue.queue.size());
    }

    if (!proxiedRequest) {
        Debug::log(ERR, "Couldn't create an async proxy request struct?");
        response.send(Pistache::Http::Code::Internal_Server_Error, "Internal Proxy Error");
        return;
    }

    // TODO: add an option to limit the amount of threads (akin to a Java ThreadPool iirc it was called)
    proxiedRequest->requestThread = std::thread([proxiedRequest, this]() {
        proxyPassInternal(proxiedRequest->req, proxiedRequest->response, true);
        std::lock_guard<std::mutex> lg(*m_asyncProxyQueue.queueMutex);
        std::erase(m_asyncProxyQueue.queue, proxiedRequest);
        Debug::log(TRACE, "proxyPassAsync: request done, queue size {}", m_asyncProxyQueue.queue.size());
    });
    proxiedRequest->requestThread.detach();
}

void CServerHandler::proxyPassInternal(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response, bool async) {
    const std::string FORWARD_ADDR = g_pConfig->m_config.forward_address;

    Debug::log(TRACE, "Method ({}): Forwarding to {}", (uint32_t)req.method(), FORWARD_ADDR + req.resource());

    Pistache::Http::Experimental::Client client;
    client.init(Pistache::Http::Experimental::Client::options().maxConnectionsPerHost(32).maxResponseSize(g_pConfig->m_config.max_request_size).threads(4));

    auto builder = client.prepareRequest(FORWARD_ADDR + req.resource(), req.method());
    builder.body(req.body());
    for (auto it = req.cookies().begin(); it != req.cookies().end(); ++it) {
        builder.cookie(*it);
    }
    builder.params(req.query());
    const auto HEADERS = req.headers().list();
    for (auto& h : HEADERS) {
        const auto HNAME = std::string_view{h->name()};
        if (HNAME == "Cache-Control" || HNAME == "Connection" || HNAME == "Content-Length" || HNAME == "Accept-Encoding") {
            Debug::log(TRACE, "Header in: {}: {} (DROPPED)", h->name(), req.headers().getRaw(h->name()).value());
            continue;
        }

        // FIXME: this should be possible once pistache allows for live reading of T-E?
        // for now, we wait for everything forever...
        // same as the todo further below, essentially
        if (HNAME == "Accept" && req.headers().getRaw(h->name()).value().contains("text/event-stream")) {
            Debug::log(TRACE, "FIXME: proxyPassInternal: text/event-stream not supported");
            response.send(Pistache::Http::Code::Internal_Server_Error, "Internal server error");
            client.shutdown();
            return;
        }

        Debug::log(TRACE, "Header in: {}: {}", h->name(), req.headers().getRaw(h->name()).value());
        builder.header(h);
    }
    builder.header(std::make_shared<Pistache::Http::Header::Connection>(Pistache::Http::ConnectionControl::KeepAlive));

    builder.timeout(std::chrono::seconds(g_pConfig->m_config.proxy_timeout_sec));

    // TODO: implement streaming for git's large objects?

    auto resp = builder.send();
    resp.then(
        [&](Pistache::Http::Response resp) {
            const auto HEADERSRESP = resp.headers().list();

            for (auto& h : HEADERSRESP) {
                if (std::string_view{h->name()} == "Transfer-Encoding") {
                    Debug::log(TRACE, "Header out: {}: {} (DROPPED)", h->name(), resp.headers().getRaw(h->name()).value());
                    continue;
                }

                Debug::log(TRACE, "Header out: {}: {}", h->name(), resp.headers().getRaw(h->name()).value());
                response.headers().add(h);
            }

            for (auto it = resp.cookies().begin(); it != resp.cookies().end(); ++it) {
                std::stringstream ss;
                ss << *it;
                response.cookies().add(*it);

                Debug::log(TRACE, "Header out: Set-Cookie: {}", ss.str());
            }

            auto enc = req.getBestAcceptEncoding();
            response.setCompression(enc);
            response.send(resp.code(), resp.body());
        },
        [&](std::exception_ptr e) {
            try {
                std::rethrow_exception(e);
            } catch (std::exception& e) { Debug::log(ERR, "Proxy failed: {}", e.what()); } catch (const std::string& e) {
                Debug::log(ERR, "Proxy failed: {}", e);
            } catch (const char* e) { Debug::log(ERR, "Proxy failed: {}", e); } catch (...) {
                Debug::log(ERR, "Proxy failed: God knows why.");
            }

            response.send(Pistache::Http::Code::Internal_Server_Error, "Internal Proxy Error");
        });
    Pistache::Async::Barrier<Pistache::Http::Response> b(resp);
    b.wait_for(std::chrono::seconds(g_pConfig->m_config.proxy_timeout_sec));

    client.shutdown();
}