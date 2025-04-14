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
#include "../debug/log.hpp"
#include "../GlobalState.hpp"
#include "../config/Config.hpp"

#include <fstream>
#include <filesystem>
#include <random>
#include <sstream>

#include <tinylates/tinylates.hpp>
#include <fmt/format.h>
#include <glaze/glaze.hpp>
#include <openssl/evp.h>

constexpr const uint64_t TOKEN_MAX_AGE_MS  = 1000 * 60 * 60; // 1hr
constexpr const char*    TOKEN_COOKIE_NAME = "checkpoint-token";

static std::string readFileAsText(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) {
        throw std::runtime_error("Could not open file: " + path);
    }
    auto res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    if (!res.empty() && res.back() == '\n') {
        res.pop_back();
    }
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

std::string CServerHandler::fingerprintForRequest(const Pistache::Http::Request& req) {
    const auto                                                    HEADERS = req.headers();
    std::shared_ptr<const Pistache::Http::Header::AcceptEncoding> acceptEncodingHeader;
    std::shared_ptr<const Pistache::Http::Header::UserAgent>      userAgentHeader;
    std::shared_ptr<const CFConnectingIPHeader>                   cfHeader;
    std::shared_ptr<const AcceptLanguageHeader>                   languageHeader;

    std::string                                                   input = "checkpoint-";

    try {
        cfHeader = Pistache::Http::Header::header_cast<CFConnectingIPHeader>(HEADERS.get("cf-connecting-ip"));
    } catch (std::exception& e) {
        ; // silent ignore
    }

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

    if (cfHeader)
        input += cfHeader->ip();
    // TODO: those seem to change. Find better things to hash.
    // if (acceptEncodingHeader)
    //     input += HEADERS.getRaw("Accept-Encoding").value();
    // if (languageHeader)
    //     input += languageHeader->language();
    if (userAgentHeader)
        input += userAgentHeader->agent();

    input += req.address().host();

    return g_pCrypto->sha256(input);
}

bool CServerHandler::isResourceCheckpoint(const std::string_view& res) {
    return res == "/checkpoint/NotoSans.woff";
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

    Debug::log(LOG, " | Request author: IP {}", req.address().host());
    if (cfHeader)
        Debug::log(LOG, " | CloudFlare reports IP: {}", cfHeader->ip());
    else
        Debug::log(TRACE, "Connection does not come through CloudFlare");

    if (userAgentHeader)
        Debug::log(LOG, " | UA: {}", userAgentHeader->agent());

    if (req.resource() == "/checkpoint/challenge") {
        if (req.method() == Pistache::Http::Method::Post)
            challengeSubmitted(req, response);
        else
            response.send(Pistache::Http::Code::Bad_Request, "Bad Request");
        return;
    }

    if (isResourceCheckpoint(req.resource())) {
        std::filesystem::path html_dir_from_config = g_pConfig->m_config.html_dir;
        std::filesystem::path base_html_path;
        if (html_dir_from_config.is_absolute()) {
            base_html_path = html_dir_from_config;
        } else {
            base_html_path = std::filesystem::path(g_pGlobalState->cwd) / html_dir_from_config;
        }

        // assumes resource paths always start with /checkpoint/, does this hold?
        std::string resource_sub_path_str;
        size_t prefix_pos = req.resource().find("/checkpoint/");
        if (prefix_pos != std::string::npos) {
             resource_sub_path_str = req.resource().substr(prefix_pos + 12); // len "/checkpoint/"
        }

        std::filesystem::path final_resource_path = base_html_path / resource_sub_path_str;

        try {
            std::error_code ec;
            final_resource_path = canonical(final_resource_path, ec);
            if (ec) {
                 Debug::log(WARN, "Cannot resolve requested resource path '{}': {}", final_resource_path.string(), ec.message());
                 response.send(Pistache::Http::Code::Not_Found, "Resource not found");
                 return;
            }

             auto [base_mismatch, file_mismatch] = std::mismatch(base_html_path.begin(), base_html_path.end(), final_resource_path.begin());
             if (base_mismatch != base_html_path.end()) {
                 Debug::log(WARN, "Attempted directory traversal: {}", final_resource_path.string());
                 response.send(Pistache::Http::Code::Forbidden, "Forbidden");
                 return;
             }

            std::string file_content = readFileAsText(final_resource_path.string());
            // TODO: probably want to determine MIME type from file extension
            response.send(Pistache::Http::Code::Ok, file_content);
        } catch (const std::filesystem::filesystem_error& e) {
            // canonical might throw filesystem_error
            Debug::log(WARN, "Filesystem error accessing resource '{}': {}", final_resource_path.string(), e.what());
            response.send(Pistache::Http::Code::Not_Found, "Resource not found");
        } catch (const std::runtime_error& e) {
            // readFileAsText throws if file not found or unreadable
            Debug::log(WARN, "Failed to read checkpoint resource '{}': {}", final_resource_path.string(), e.what());
            response.send(Pistache::Http::Code::Not_Found, "Resource not found");
        }

        return; // handled
    }


    if (g_pConfig->m_config.git_host) {
        // TODO: ratelimit this, probably.

        const auto RES              = req.resource();
        bool       validGitResource = RES.ends_with("/info/refs") || RES.ends_with("/info/packs") || RES.ends_with("HEAD") || RES.ends_with(".git");

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

    serveStop(req, response);
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

void CServerHandler::serveStop(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    // for the sake of consistency
    std::filesystem::path html_dir_from_config = g_pConfig->m_config.html_dir;
    std::filesystem::path base_html_path;
    if (html_dir_from_config.is_absolute()) {
        base_html_path = html_dir_from_config;
    } else {
        base_html_path = std::filesystem::path(g_pGlobalState->cwd) / html_dir_from_config;
    }

    std::error_code ec;
    base_html_path = std::filesystem::canonical(base_html_path, ec);
    if (ec) {
        Debug::log(CRIT, "Cannot resolve configured html_dir '{}': {}", g_pConfig->m_config.html_dir, ec.message());
        // we dont wanna expose internal path in response
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server Configuration Error (HTML Path)");
        return;
    }

    std::filesystem::path index_file_path = base_html_path / "index.min.html";

    std::string page_index_content;
    try {
        page_index_content = readFileAsText(index_file_path.string());
    } catch (const std::runtime_error& e) {
        Debug::log(CRIT, "Cannot read index file '{}': {}", index_file_path.string(), e.what());
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server Configuration Error (Index File)");
        return;
    }

    CTinylates page(page_index_content);
    page.setTemplateRoot(base_html_path.string());

    const auto     NONCE      = generateNonce();
    constexpr auto DIFFICULTY = 4;
    const auto CHALLENGE = CChallenge(fingerprintForRequest(req), NONCE, DIFFICULTY);

    page.add("challengeDifficulty", CTinylatesProp(std::to_string(DIFFICULTY)));
    page.add("challengeNonce", CTinylatesProp(NONCE));
    page.add("challengeSignature", CTinylatesProp(CHALLENGE.signature()));
    page.add("challengeFingerprint", CTinylatesProp(CHALLENGE.fingerprint()));
    page.add("checkpointVersion", CTinylatesProp(CHECKPOINT_VERSION));

    response.send(Pistache::Http::Code::Ok, page.render().value_or("error rendering challenge page"));
}


void CServerHandler::proxyPass(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter& response) {
    const std::string FORWARD_ADDR = g_pConfig->m_config.forward_address;

    Debug::log(TRACE, "Method ({}): Forwarding to {}", (uint32_t)req.method(), FORWARD_ADDR + req.resource());

    Pistache::Http::Experimental::Client client;
    client.init(Pistache::Http::Experimental::Client::options().maxConnectionsPerHost(8).maxResponseSize(g_pConfig->m_config.max_request_size).threads(1));

    auto builder = client.prepareRequest(FORWARD_ADDR + req.resource(), req.method());
    builder.body(req.body());
    for (auto it = req.cookies().begin(); it != req.cookies().end(); ++it) {
        builder.cookie(*it);
    }
    builder.params(req.query());
    const auto HEADERS = req.headers().list();
    for (auto& h : HEADERS) {
        // FIXME: why does this break e.g. gitea if we include it?
        const auto HNAME = std::string_view{h->name()};
        if (HNAME == "Cache-Control" || HNAME == "Connection" || HNAME == "Content-Length") {
            Debug::log(TRACE, "Header in: {}: {} (DROPPED)", h->name(), req.headers().getRaw(h->name()).value());
            continue;
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
                response.headers().add(std::make_shared<SetCookieHeader>(ss.str()));

                Debug::log(TRACE, "Header out: Set-Cookie: {}", ss.str());
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

    client.shutdown();
}