#include "RequestUtils.hpp"

#include "../core/Crypto.hpp"

#include "../headers/authorization.hpp"
#include "../headers/cfHeader.hpp"
#include "../headers/xforwardfor.hpp"
#include "../headers/gitProtocolHeader.hpp"
#include "../headers/wwwAuthenticateHeader.hpp"
#include "../headers/acceptLanguageHeader.hpp"
#include "../headers/setCookieHeader.hpp"
#include "../headers/xrealip.hpp"

std::string NRequestUtils::fingerprintForRequest(const Pistache::Http::Request& req) {
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

std::string NRequestUtils::ipForRequest(const Pistache::Http::Request& req) {
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