#include "Crypto.hpp"

#include "../GlobalState.hpp"
#include "../config/Config.hpp"
#include "../debug/log.hpp"
#include "../helpers/FsUtils.hpp"

#include <filesystem>
#include <vector>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fmt/format.h>

constexpr const char* KEY_FILENAME = "privateKey.key";

CCrypto::CCrypto() {
    if (!std::filesystem::exists(NFsUtils::dataDir() + "/" + KEY_FILENAME)) {
        Debug::log(LOG, "No private key, generating one.");
        if (!genKey()) {
            Debug::log(CRIT, "Couldn't generate a key.");
            throw std::runtime_error("Keygen failed");
        }
    } else {
        auto f = fopen((NFsUtils::dataDir() + "/" + KEY_FILENAME).c_str(), "r");
        PEM_read_PrivateKey(f, &m_evpPkey, nullptr, nullptr);
        fclose(f);
    }

    if (!m_evpPkey) {
        Debug::log(CRIT, "Couldn't read the key.");
        throw std::runtime_error("Key read openssl failed");
    }

    Debug::log(LOG, "Read private key");
}

CCrypto::~CCrypto() {
    if (m_evpPkey)
        EVP_PKEY_free(m_evpPkey);
}

std::vector<uint8_t> CCrypto::toByteArr(const std::string_view& s) {
    std::vector<uint8_t> inAsHash;
    inAsHash.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        uint8_t byte = std::stoi(std::string{s.substr(i, 2)}, nullptr, 16);
        inAsHash.emplace_back(byte);
    }
    return inAsHash;
}

std::string CCrypto::sha256(const std::string& in) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return "";

    if (!EVP_DigestInit(ctx, EVP_sha256())) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (!EVP_DigestUpdate(ctx, in.c_str(), in.size())) {
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

    EVP_MD_CTX_free(ctx);

    return ss.str();
}

bool CCrypto::genKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);

    if (!ctx)
        return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_keygen(ctx, &m_evpPkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    auto f = fopen((NFsUtils::dataDir() + "/" + KEY_FILENAME).c_str(), "w");
    PEM_write_PrivateKey(f, m_evpPkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    EVP_PKEY_CTX_free(ctx);

    return true;
}

std::string CCrypto::sign(const std::string& in) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return "";

    if (!EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, m_evpPkey)) {
        Debug::log(ERR, "CCrypto::sign: EVP_DigestSignInit: err {}", ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        return "";
    }

    size_t len = 0;

    if (!EVP_DigestSign(ctx, nullptr, &len, (const unsigned char*)in.c_str(), in.size())) {
        Debug::log(ERR, "CCrypto::sign: EVP_DigestSign: err {}", ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (len <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::vector<uint8_t> buf;
    buf.resize(len);

    if (!EVP_DigestSign(ctx, buf.data(), &len, (const unsigned char*)in.c_str(), in.size())) {
        Debug::log(ERR, "CCrypto::sign: EVP_DigestSign: err {}", ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::stringstream ss;
    for (size_t i = 0; i < buf.size(); ++i) {
        ss << fmt::format("{:02x}", buf[i]);
    }

    EVP_MD_CTX_free(ctx);

    return ss.str();
}

bool CCrypto::verifySignature(const std::string& in, const std::string& sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    if (!EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, m_evpPkey)) {
        Debug::log(ERR, "CCrypto::verifySignature: EVP_DigestVerifyInit: err {}", ERR_error_string(ERR_get_error(), nullptr));
        EVP_MD_CTX_free(ctx);
        return false;
    }

    auto sigAsArr = toByteArr(sig);

    int  ret = EVP_DigestVerify(ctx, sigAsArr.data(), sigAsArr.size(), (const unsigned char*)in.c_str(), in.size());

    if (ret == 1) {
        // match
        EVP_MD_CTX_free(ctx);
        return true;
    }

    if (ret == 0) {
        // no match
        EVP_MD_CTX_free(ctx);
        return false;
    }

    Debug::log(ERR, "CCrypto::verifySignature: EVP_DigestVerify: err {}", ERR_error_string(ERR_get_error(), nullptr));

    // invalid sig??
    EVP_MD_CTX_free(ctx);
    return false;
}
