#include <pistache/http_headers.h>
#include <pistache/net.h>

class AcceptLanguageHeader : public Pistache::Http::Header::Header {
  public:
    NAME("Accept-Language");

    AcceptLanguageHeader() = default;

    void parse(const std::string& str) override {
        m_language = str;
    }

    void write(std::ostream& os) const override {
        os << m_language;
    }

    std::string language() const {
        return m_language;
    }

  private:
    std::string m_language = "";
};