#include <pistache/http_headers.h>
#include <pistache/net.h>

class XRealIPHeader : public Pistache::Http::Header::Header {
  public:
    NAME("X-Real-IP");

    XRealIPHeader() = default;

    void parse(const std::string& str) override {
        m_ip = str;
    }

    void write(std::ostream& os) const override {
        os << m_ip;
    }

    std::string ip() const {
        return m_ip;
    }

  private:
    std::string m_ip = "";
};