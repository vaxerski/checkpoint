#include <iostream>
#include <filesystem>
#include <pistache/common.h>
#include <pistache/cookie.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/net.h>
#include <pistache/peer.h>

#include "headers/authorization.hpp"
#include "headers/xforwardfor.hpp"
#include "headers/cfHeader.hpp"
#include "headers/gitProtocolHeader.hpp"
#include "headers/acceptLanguageHeader.hpp"

#include "debug/log.hpp"

#include "core/Handler.hpp"
#include "core/Db.hpp"

#include "config/Config.hpp"

#include "GlobalState.hpp"

#include <signal.h>

int main(int argc, char** argv, char** envp) {

    if (argc < 2) {
        Debug::log(CRIT, "Missing param for websites storage");
        return 1;
    }

    std::vector<std::string> ARGS{};
    ARGS.resize(argc);
    for (int i = 0; i < argc; ++i) {
        ARGS[i] = std::string{argv[i]};
    }

    std::vector<std::string> command;

    g_pGlobalState->cwd = std::filesystem::current_path();

    for (int i = 1; i < argc; ++i) {
        if (ARGS[i].starts_with("-")) {
            if (ARGS[i] == "--help" || ARGS[i] == "-h") {
                std::cout << "-h [html_root] -p [port]\n";
                return 0;
            } else if ((ARGS[i] == "--config" || ARGS[i] == "-c") && i + 1 < argc) {
                g_pGlobalState->configPath = ARGS[i + 1];
                i++;
            } else {
                std::cerr << "Unrecognized / invalid use of option " << ARGS[i] << "\nContinuing...\n";
                continue;
            }
        } else
            command.push_back(ARGS[i]);
    }

    g_pConfig = std::make_unique<CConfig>();

    if (g_pConfig->m_config.html_dir.empty() || g_pConfig->m_config.data_dir.empty())
        return 1;

    sigset_t signals;
    if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGTERM) != 0 || sigaddset(&signals, SIGINT) != 0 || sigaddset(&signals, SIGQUIT) != 0 ||
        sigaddset(&signals, SIGPIPE) != 0 || sigaddset(&signals, SIGALRM) != 0 || sigprocmask(SIG_BLOCK, &signals, nullptr) != 0)
        return 1;

    int               threads = 1;
    Pistache::Address address = {Pistache::Ipv4::any(), (uint16_t)g_pConfig->m_config.port};
    Debug::log(LOG, "Starting the server on {}:{}\n", address.host(), address.port().toString());

    Pistache::Http::Header::Registry::instance().registerHeader<CFConnectingIPHeader>();
    Pistache::Http::Header::Registry::instance().registerHeader<XForwardedForHeader>();
    Pistache::Http::Header::Registry::instance().registerHeader<GitProtocolHeader>();
    Pistache::Http::Header::Registry::instance().registerHeader<AcceptLanguageHeader>();

    g_pDB = std::make_unique<CDatabase>();

    auto endpoint = std::make_unique<Pistache::Http::Endpoint>(address);
    auto opts     = Pistache::Http::Endpoint::options().threads(threads).flags(Pistache::Tcp::Options::ReuseAddr | Pistache::Tcp::Options::ReusePort);
    opts.maxRequestSize(g_pConfig->m_config.max_request_size);
    endpoint->init(opts);
    auto handler = Pistache::Http::make_handler<CServerHandler>();
    handler->init();
    endpoint->setHandler(handler);

    endpoint->serveThreaded();

    bool terminate = false;
    while (!terminate) {
        int number = 0;
        int status = sigwait(&signals, &number);
        if (status != 0) {
            Debug::log(CRIT, "sigwait threw {} :(", status);
            break;
        }

        Debug::log(LOG, "Caught signal {}", number);

        switch (number) {
            case SIGINT: terminate = true; break;
            case SIGTERM: terminate = true; break;
            case SIGQUIT: terminate = true; break;
            case SIGPIPE: break;
            case SIGALRM: break;
        }
    }

    sigprocmask(SIG_UNBLOCK, &signals, nullptr);

    Debug::log(LOG, "Shutting down, bye!");

    handler->finish();
    endpoint->shutdown();
    endpoint = nullptr;

    return 0;
}