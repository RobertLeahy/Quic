/**
 *  \file
 */

#pragma once

#include <cstddef>
#include <system_error>
#include <boost/asio/buffers_iterator.hpp>

namespace quic {

namespace detail {

enum class packet_error {
  success = 0,
  no_public_flags
};

std::error_code make_error_code(packet_error) noexcept;

}

template<typename ConstBufferSequence>
std::byte public_flags(ConstBufferSequence cb,
                       std::error_code& ec) noexcept
{
  ec.clear();
  using buffers_iterator = boost::asio::buffers_iterator<ConstBufferSequence,
                                                         std::byte>;
  auto begin = buffers_iterator::begin(cb);
  auto end = buffers_iterator::end(cb);
  if (begin == end) {
    ec = make_error_code(detail::packet_error::no_public_flags);
    return std::byte{};
  }
  return *begin;
}

namespace detail {

template<std::byte Mask,
         typename ConstBufferSequence>
bool public_flag(ConstBufferSequence cb,
                 std::error_code& ec) noexcept
{
  ec.clear();
  auto b = quic::public_flags(cb,
                              ec);
  if (ec) {
    return false;
  }
  return (Mask & b) == Mask;
}

}

template<typename ConstBufferSequence>
bool public_flag_version(ConstBufferSequence cb,
                         std::error_code& ec) noexcept
{
  return detail::public_flag<std::byte{1}>(cb,
                                           ec);
}

template<typename ConstBufferSequence>
bool public_flag_reset(ConstBufferSequence cb,
                       std::error_code& ec) noexcept
{
  return detail::public_flag<std::byte{2}>(cb,
                                           ec);
}

template<typename ConstBufferSequence>
bool public_flag_diversification_nonce(ConstBufferSequence cb,
                                       std::error_code& ec) noexcept
{
  return detail::public_flag<std::byte{4}>(cb,
                                           ec);
}

template<typename ConstBufferSequence>
bool public_flag_connection_id(ConstBufferSequence cb,
                               std::error_code& ec) noexcept
{
  return detail::public_flag<std::byte{8}>(cb,
                                           ec);
}

}
