#include <pistache/http_headers.h>
#include <pistache/net.h>

class XForwardedForHeader : public Pistache::Http::Header::Header {
  public:
    NAME("X-Forwarded-For");

    XForwardedForHeader() = default;

    void parse(const std::string& str) override {
        m_for = str;
    }

    void write(std::ostream& os) const override {
        os << m_for;
    }

    std::string from() const {
        return m_for;
    }

  private:
    std::string m_for = "";
};