#include <quic/packet.hpp>

#include <string>
#include <system_error>
#include <boost/asio/error.hpp>

namespace quic {

namespace detail {

std::error_code make_error_code(packet_error err) noexcept {
  static const class : public std::error_category {
  public:
    virtual const char* name() const noexcept override {
      return "QUIC/Core/Packet";
    }
    virtual std::string message(int code) const override {
      switch (static_cast<packet_error>(code)) {
      case packet_error::success:
        return "Success";
      case packet_error::no_public_flags:
        return "No bytes in packet (attempting to retrieve public flags)";
      default:
        break;
      }
      return "Unknown";
    }
    virtual std::error_condition default_error_condition(int code) const noexcept override {
      switch (static_cast<packet_error>(code)) {
      case packet_error::success:
        return std::error_condition();
      case packet_error::no_public_flags:
        return make_error_code(boost::asio::error::eof).default_error_condition();
      default:
        break;
      }
      return std::error_condition(code,
                                  *this);
    }
  } category;
  return std::error_code(static_cast<int>(err),
                         category);
}

}

}
