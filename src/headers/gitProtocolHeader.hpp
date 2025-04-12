#include <pistache/http_headers.h>
#include <pistache/net.h>

class GitProtocolHeader : public Pistache::Http::Header::Header {
  public:
    NAME("Git-Protocol");

    GitProtocolHeader() = default;

    void parse(const std::string& str) override {
        m_text = str;
    }

    void write(std::ostream& os) const override {
        os << m_text;
    }

    std::string text() const {
        return m_text;
    }

  private:
    std::string m_text = "";
};