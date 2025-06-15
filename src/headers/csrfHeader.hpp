#include <pistache/http_headers.h>
#include <pistache/net.h>

class XCSRFTokenHeader : public Pistache::Http::Header::Header {
  public:
    NAME("X-Csrf-Token");

    XCSRFTokenHeader() = default;

    void parse(const std::string& str) override {
        m_data = str;
    }

    void write(std::ostream& os) const override {
        os << m_data;
    }

    std::string ip() const {
        return m_data;
    }

  private:
    std::string m_data = "";
};