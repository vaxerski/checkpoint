#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <openssl/evp.h>

class CCrypto {
  public:
    CCrypto();
    ~CCrypto();

    std::string sha256(const std::string& in);
    std::string sign(const std::string& in);
    bool        verifySignature(const std::string& in, const std::string& sig);

  private:
    EVP_PKEY*            m_evpPkey = nullptr;

    bool                 genKey();
    void                 readKey();
    std::vector<uint8_t> toByteArr(const std::string_view& s);
};

inline std::unique_ptr<CCrypto> g_pCrypto;