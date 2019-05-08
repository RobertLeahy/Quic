/**
 *  \file
 */

#pragma once

namespace quic {

template<typename Integer>
bool server_initiated(Integer id) noexcept {
  constexpr Integer mask(1);
  return bool(id & mask);
}

template<typename Integer>
bool client_initiated(Integer id) noexcept {
  return !quic::server_initiated(id);
}

template<typename Integer>
bool unidirectional(Integer id) noexcept {
  constexpr Integer mask(2);
  return bool(id & mask);
}

template<typename Integer>
bool bidirectional(Integer id) noexcept {
  return !quic::unidirectional(id);
}

}
