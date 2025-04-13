#include <pistache/http_headers.h>
#include <pistache/net.h>

class SetCookieHeader : public Pistache::Http::Header::Header {
  public:
    NAME("Set-Cookie");

    SetCookieHeader(const std::string& cookie = "") : m_cookie(cookie) {
        ;
    }

    void parse(const std::string& str) override {
        m_cookie = str;
    }

    void write(std::ostream& os) const override {
        os << m_cookie;
    }

    std::string from() const {
        return m_cookie;
    }

  private:
    std::string m_cookie = "";
};