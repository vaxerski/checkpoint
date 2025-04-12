#include "Handler.hpp"
#include "../headers/authorization.hpp"
#include "../headers/cfHeader.hpp"
#include "../headers/xforwardfor.hpp"
#include "../headers/gitProtocolHeader.hpp"
#include "../debug/log.hpp"
#include "../GlobalState.hpp"
#include "../config/Config.hpp"
#include "Db.hpp"

#include <fstream>
#include <filesystem>
#include <random>
#include <sstream>

#include <tinylates/tinylates.hpp>
#include <fmt/format.h>
#include <glaze/glaze.hpp>
#include <openssl/evp.h>

constexpr const uint64_t TOKEN_MAX_AGE_MS = 1000 * 60 * 60; // 1hr

//
static std::string readFileAsText(const std::string& path) {
    std::ifstream ifs(path);
    auto          res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    if (res.back() == '\n')
        res.pop_back();
    return res;
}

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

static std::string sha256(const std::string& string) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return "";

    if (!EVP_DigestInit(ctx, EVP_sha256())) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (!EVP_DigestUpdate(ctx, string.c_str(), string.size())) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    uint8_t buf[32];

    if (!EVP_DigestFinal(ctx, buf, nullptr)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::stringstream ss;
    for (size_t i = 0; i < 32; ++i) {
        ss << fmt::format("{:02x}", buf[i]);
    }

    return ss.str();
}

void CServerHandler::init() {
    m_client = new Pistache::Http::Experimental::Client();
    m_client->init(Pistache::Http::Experimental::Client::options().threads(1).maxConnectionsPerHost(8));
}

void CServerHandler::finish() {
    m_client->shutdown();
    delete m_client;
    m_client = nullptr;
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

    Debug::log(LOG, "Got request for: {}:{}{}", hostHeader->host(), hostHeader->port().toString(), req.resource());
    Debug::log(LOG, "Request author: IP {}", req.address().host());
    if (cfHeader)
        Debug::log(LOG, "CloudFlare reports IP: {}", cfHeader->ip());
    else
        Debug::log(WARN, "Connection does not come through CloudFlare");

    if (userAgentHeader)
        Debug::log(LOG, "UA: {}", userAgentHeader->agent());

    if (req.resource() == "/checkpoint/challenge") {
        if (req.method() == Pistache::Http::Method::Post)
            challengeSubmitted(req, response);
        else
            response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
        return;
    }

    if (g_pConfig->m_config.git_host) {
        // TODO: ratelimit and check this. This can be faked!
        if (gitProtocolHeader && userAgentHeader) {
            Debug::log(LOG, "Request looks like it is coming from git (UA + GP). Accepting.");

            proxyPass(req, response);
            return;
        } else if (userAgentHeader->agent().starts_with("git/")) {
            Debug::log(LOG, "Request looks like it is coming from git (UA git). Accepting.");

            proxyPass(req, response);
            return;
        }
    }

    if (req.cookies().has("CheckpointToken")) {
        // check the token
        const auto TOKEN = g_pDB->getToken(req.cookies().get("CheckpointToken").value);
        if (TOKEN) {
            const auto AGE = std::chrono::milliseconds(std::time(nullptr)).count() - TOKEN->epoch;
            if (AGE <= TOKEN_MAX_AGE_MS && TOKEN->ip == (cfHeader ? cfHeader->ip() : req.address().host())) {
                proxyPass(req, response);
                return;
            } else // token has been used from a different IP or is expired. Nuke it.
                g_pDB->dropToken(TOKEN->token);
        }
    }

    serveStop(req, response);
}

void CServerHandler::onTimeout(const Pistache::Http::Request& request, Pistache::Http::ResponseWriter response) {
    response.send(Pistache::Http::Code::Request_Timeout, "Timeout").then([=](ssize_t) {}, PrintException());
}

void CServerHandler::challengeSubmitted(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    const auto                                  JSON = req.body();

    std::shared_ptr<const CFConnectingIPHeader> cfHeader;
    try {
        cfHeader = Pistache::Http::Header::header_cast<CFConnectingIPHeader>(req.headers().get("cf-connecting-ip"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

    auto           json = glz::read_json<SChallengeResponse>(JSON);
    STokenResponse resp;

    if (!json) {
        resp.error = "bad input";
        response.send(Pistache::Http::Code::Bad_Request, glz::write_json(resp).value());
        return;
    }

    auto       val = json.value();

    const auto CHALLENGE = g_pDB->getChallenge(val.challenge);

    if (!CHALLENGE.has_value()) {
        resp.error = "bad challenge";
        response.send(Pistache::Http::Code::Bad_Request, glz::write_json(resp).value());
        return;
    }

    if (CHALLENGE->ip != req.address().host()) {
        resp.error = "bad challenge";
        response.send(Pistache::Http::Code::Bad_Request, glz::write_json(resp).value());
        return;
    }

    // drop challenge already.
    g_pDB->dropChallenge(val.challenge);

    // verify challenge
    const auto SHA = sha256(val.challenge + std::to_string(val.solution));

    for (int i = 0; i < CHALLENGE->difficulty; ++i) {
        if (SHA.at(i) != '0') {
            resp.error = "bad solution";
            response.send(Pistache::Http::Code::Bad_Request, glz::write_json(resp).value());
            return;
        }
    }

    // correct solution, return a token

    const auto TOKEN = generateToken();

    g_pDB->addToken(SDatabaseTokenEntry{.token = TOKEN, .ip = (cfHeader ? cfHeader->ip() : req.address().host())});

    resp.success = true;
    resp.token   = TOKEN;

    response.send(Pistache::Http::Code::Ok, glz::write_json(resp).value());
}

void CServerHandler::serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    static const auto       PATH       = std::filesystem::canonical(g_pGlobalState->cwd + "/" + g_pConfig->m_config.html_dir).string();
    /* static */ const auto PAGE_INDEX = readFileAsText(PATH + "/index.min.html");
    CTinylates              page(PAGE_INDEX);
    page.setTemplateRoot(PATH);

    const auto NONCE      = generateNonce();
    const auto DIFFICULTY = 4;

    g_pDB->addChallenge(SDatabaseChallengeEntry{.nonce = NONCE, .difficulty = DIFFICULTY, .ip = req.address().host()});

    page.add("challengeDifficulty", CTinylatesProp(std::to_string(DIFFICULTY)));
    page.add("challengeNonce", CTinylatesProp(NONCE));
    page.add("checkpointVersion", CTinylatesProp(CHECKPOINT_VERSION));
    response.send(Pistache::Http::Code::Ok, page.render().value_or("error"));
}

void CServerHandler::proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    const std::string FORWARD_ADDR = g_pConfig->m_config.forward_address;

    Debug::log(LOG, "Method ({}): Forwarding to {}", (uint32_t)req.method(), FORWARD_ADDR + req.resource());

    auto builder = m_client->prepareRequest(FORWARD_ADDR + req.resource(), req.method());
    builder.body(req.body());
    for (auto it = req.cookies().begin(); it != req.cookies().end(); ++it) {
        builder.cookie(*it);
    }
    const auto HEADERS = req.headers().list();
    for (auto& h : HEADERS) {
        // FIXME: why does this break e.g. gitea if we include it?
        if (std::string_view{h->name()} == "Host") {
            Debug::log(LOG, "Header in: {}: {} (DROPPED)", h->name(), req.headers().getRaw(h->name()).value());
            continue;
        }

        Debug::log(LOG, "Header in: {}: {}", h->name(), req.headers().getRaw(h->name()).value());
        builder.header(h);
    }
    builder.timeout(std::chrono::seconds(g_pConfig->m_config.proxy_timeout_sec));

    // TODO: implement streaming for git's large objects?

    auto resp = builder.send();
    resp.then(
        [&](Pistache::Http::Response resp) {
            const auto HEADERSRESP = resp.headers().list();

            for (auto& h : HEADERSRESP) {
                if (std::string_view{h->name()} == "Transfer-Encoding") {
                    Debug::log(LOG, "Header out: {}: {} (DROPPED)", h->name(), resp.headers().getRaw(h->name()).value());
                    continue;
                }
                
                Debug::log(LOG, "Header out: {}: {}", h->name(), resp.headers().getRaw(h->name()).value());
                response.headers().add(h);
            }

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
}