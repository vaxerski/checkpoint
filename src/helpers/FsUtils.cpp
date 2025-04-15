#include "FsUtils.hpp"

#include <fstream>

#include "../GlobalState.hpp"
#include "../config/Config.hpp"

bool NFsUtils::isAbsolute(const std::string& sv) {
    return sv.size() > 0 && (*sv.begin() == '/' || *sv.begin() == '~');
}

std::expected<std::string, std::string> NFsUtils::readFileAsString(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.good())
        return std::unexpected("No file");
    auto res = std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    if (res.back() == '\n')
        res.pop_back();
    return res;
}

std::string NFsUtils::htmlPath(const std::string& resource) {
    static const std::string htmlRoot = isAbsolute(g_pConfig->m_config.html_dir) ? g_pConfig->m_config.html_dir : g_pGlobalState->cwd + "/" + g_pConfig->m_config.html_dir;
    return htmlRoot + "/" + resource;
}

std::string NFsUtils::dataDir() {
    static const std::string dataRoot = isAbsolute(g_pConfig->m_config.data_dir) ? g_pConfig->m_config.data_dir : g_pGlobalState->cwd + "/" + g_pConfig->m_config.data_dir;
    return dataRoot;
}
