#include <quic/stream_id.hpp>

#include <catch2/catch.hpp>

namespace quic::tests {
namespace {

TEST_CASE("server_initiated",
          "[quic][stream_id]")
{
  CHECK(server_initiated(41));
  CHECK_FALSE(server_initiated(40));
}

TEST_CASE("client_initiated",
          "[quic][stream_id]")
{
  CHECK_FALSE(client_initiated(41));
  CHECK(client_initiated(40));
}

TEST_CASE("unidirectional",
          "[quic][stream_id]")
{
  CHECK(unidirectional(42));
  CHECK_FALSE(unidirectional(41));
}

TEST_CASE("bidirectional",
          "[quic][stream_id]")
{
  CHECK_FALSE(bidirectional(42));
  CHECK(bidirectional(41));
}

}
}
