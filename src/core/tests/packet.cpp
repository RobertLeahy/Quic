#include <quic/packet.hpp>

#include <cstddef>
#include <system_error>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>

#include <catch2/catch.hpp>

namespace quic::tests {
namespace {

TEST_CASE("public_flags",
          "[quic][packet][public_flags]")
{
  std::error_code ec;
  SECTION("Empty") {
    boost::asio::const_buffer cb;
    public_flags(cb,
                 ec);
    CHECK(ec);
    auto condition = make_error_code(boost::asio::error::eof).default_error_condition();
    CHECK(condition == ec.default_error_condition());
  }
  SECTION("Single byte") {
    const char buffer[] = {3};
    std::byte b = public_flags(boost::asio::buffer(buffer),
                               ec);
    REQUIRE_FALSE(ec);
    CHECK(std::byte{3} == b);
  }
  SECTION("Multiple bytes") {
    const char buffer[] = {3, 4};
    std::byte b = public_flags(boost::asio::buffer(buffer),
                               ec);
    REQUIRE_FALSE(ec);
    CHECK(std::byte{3} == b);
  }
}

TEST_CASE("public_flag_version",
          "[quic][packet][public_flags]")
{
  std::error_code ec;
  SECTION("Empty") {
    boost::asio::const_buffer cb;
    public_flag_version(cb,
                        ec);
    CHECK(ec);
    auto condition = make_error_code(boost::asio::error::eof).default_error_condition();
    CHECK(condition == ec.default_error_condition());
  }
  SECTION("Set") {
    const unsigned char buffer[] = {255};
    auto b = public_flag_version(boost::asio::buffer(buffer),
                                 ec);
    REQUIRE_FALSE(ec);
    CHECK(b);
  }
  SECTION("Unset") {
    const unsigned char buffer[] = {255 - 1};
    auto b = public_flag_version(boost::asio::buffer(buffer),
                                 ec);
    REQUIRE_FALSE(ec);
    CHECK_FALSE(b);
  }
}

TEST_CASE("public_flag_reset",
          "[quic][packet][public_flags]")
{
  std::error_code ec;
  SECTION("Empty") {
    boost::asio::const_buffer cb;
    public_flag_reset(cb,
                      ec);
    CHECK(ec);
    auto condition = make_error_code(boost::asio::error::eof).default_error_condition();
    CHECK(condition == ec.default_error_condition());
  }
  SECTION("Set") {
    const unsigned char buffer[] = {255};
    auto b = public_flag_reset(boost::asio::buffer(buffer),
                               ec);
    REQUIRE_FALSE(ec);
    CHECK(b);
  }
  SECTION("Unset") {
    const unsigned char buffer[] = {255 - 2};
    auto b = public_flag_reset(boost::asio::buffer(buffer),
                               ec);
    REQUIRE_FALSE(ec);
    CHECK_FALSE(b);
  }
}

TEST_CASE("public_flag_diversification_nonce",
          "[quic][packet][public_flags]")
{
  std::error_code ec;
  SECTION("Empty") {
    boost::asio::const_buffer cb;
    public_flag_diversification_nonce(cb,
                                      ec);
    CHECK(ec);
    auto condition = make_error_code(boost::asio::error::eof).default_error_condition();
    CHECK(condition == ec.default_error_condition());
  }
  SECTION("Set") {
    const unsigned char buffer[] = {255};
    auto b = public_flag_diversification_nonce(boost::asio::buffer(buffer),
                                               ec);
    REQUIRE_FALSE(ec);
    CHECK(b);
  }
  SECTION("Unset") {
    const unsigned char buffer[] = {255 - 4};
    auto b = public_flag_diversification_nonce(boost::asio::buffer(buffer),
                                               ec);
    REQUIRE_FALSE(ec);
    CHECK_FALSE(b);
  }
}

TEST_CASE("public_flag_connection_id",
          "[quic][packet][public_flags]")
{
  std::error_code ec;
  SECTION("Empty") {
    boost::asio::const_buffer cb;
    public_flag_connection_id(cb,
                              ec);
    CHECK(ec);
    auto condition = make_error_code(boost::asio::error::eof).default_error_condition();
    CHECK(condition == ec.default_error_condition());
  }
  SECTION("Set") {
    const unsigned char buffer[] = {255};
    auto b = public_flag_connection_id(boost::asio::buffer(buffer),
                                       ec);
    REQUIRE_FALSE(ec);
    CHECK(b);
  }
  SECTION("Unset") {
    const unsigned char buffer[] = {255 - 8};
    auto b = public_flag_connection_id(boost::asio::buffer(buffer),
                                       ec);
    REQUIRE_FALSE(ec);
    CHECK_FALSE(b);
  }
}

}
}
