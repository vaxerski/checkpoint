#include <pistache/http_headers.h>
#include <pistache/net.h>

class AuthorizationHeader : public Pistache::Http::Header::Header {
  public:
    NAME("Authorization");

    AuthorizationHeader() = default;

    void parse(const std::string& str) override {
        m_token = str;
    }

    void write(std::ostream& os) const override {
        os << m_token;
    }

    std::string token() const {
        return m_token;
    }

  private:
    std::string m_token = "";
};